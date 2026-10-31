//! Driving the macOS guest through `limactl`. Lima owns the VM lifecycle
//! (IPSW install, user, SSH); this module only ever shells into it, copies
//! binaries in, and wires the instance's extra NICs to our segment sockets.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result, bail};

use crate::frame::{Mac, fmt_mac, parse_mac};

#[derive(Clone)]
pub struct Lima {
    pub instance: String,
}

impl Lima {
    fn limactl(&self) -> Command {
        let mut c = Command::new("limactl");
        c.env("LIMA_SHELLENV_BLOCK", "*");
        c
    }

    pub fn status(&self) -> Result<String> {
        let out = self
            .limactl()
            .args(["list", "--format", "{{.Status}}", &self.instance])
            .output()
            .context("running limactl list (is lima installed?)")?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn checked(&self, args: &[&str]) -> Result<String> {
        let out = self.limactl().args(args).output().with_context(|| format!("limactl {}", args.join(" ")))?;
        if !out.status.success() {
            bail!("limactl {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Point the instance's extra NICs at our segment sockets, each with a
    /// fixed MAC so the guest-side interface can be found by MAC rather than
    /// by `enN` (A002: interface numbering is never a stable identifier —
    /// that holds in a VM too).
    pub fn set_networks(&self, nics: &[(&std::path::Path, Mac)]) -> Result<()> {
        let list = nics
            .iter()
            .map(|(p, m)| format!(r#"{{"socket":"{}","macAddress":"{}"}}"#, p.display(), fmt_mac(m)))
            .collect::<Vec<_>>()
            .join(",");
        self.checked(&["edit", "--tty=false", &self.instance, "--set", &format!(".networks = [{list}]")])?;
        Ok(())
    }

    /// `template:macos-26` keeps `video.display: default` because the
    /// INSTALLER needs a display — but every later start of that instance
    /// then dies in lima 2.1.1's `StartGraphicApplication` with a SIGTRAP
    /// when launched from a non-GUI process (measured: a plain
    /// `limactl start --tty=false` crashes identically, socket NICs or not).
    /// The cases never need a screen, so run headless.
    pub fn ensure_headless(&self) -> Result<()> {
        self.checked(&["edit", "--tty=false", &self.instance, "--set", r#".video.display = "none""#]).map(|_| ())
    }

    pub fn start(&self) -> Result<()> {
        self.checked(&["start", "--tty=false", &self.instance]).map(|_| ())
    }

    pub fn stop(&self) -> Result<()> {
        self.checked(&["stop", &self.instance]).map(|_| ())
    }

    pub fn copy_in(&self, host: &std::path::Path, guest: &str) -> Result<()> {
        self.checked(&["copy", &host.display().to_string(), &format!("{}:{guest}", self.instance)]).map(|_| ())
    }

    fn shell_cmd(&self, script: &str) -> Command {
        let mut c = self.limactl();
        c.args(["shell", "--workdir", "/", &self.instance, "sh", "-c", script]);
        c
    }

    /// Lima's macOS guest ships WITHOUT passwordless sudo (the generated
    /// password sits in the guest's `~/password`), and every case needs
    /// root for ifconfig/pf. Idempotent: a no-op once the drop-in exists.
    /// Guest-only — this is a disposable test VM, never a real Mac.
    pub fn ensure_sudo(&self) -> Result<()> {
        self.sh(
            "sudo -n true 2>/dev/null || { sudo -S -p '' sh -c \
             \"echo '$(whoami) ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/ipauro-vmlab && chmod 440 /etc/sudoers.d/ipauro-vmlab\" \
             < ~/password && sudo -n true; }",
        )
        .map(|_| ())
        .context("provisioning passwordless sudo in the guest")
    }

    /// Run `script` under `sh -c` in the guest; fail on non-zero exit.
    pub fn sh(&self, script: &str) -> Result<String> {
        let out = self.shell_cmd(script).output().with_context(|| format!("guest: {script}"))?;
        if !out.status.success() {
            bail!(
                "guest command failed ({}): {script}\nstdout: {}\nstderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Spawn `script` in the guest with stdin/stdout piped; every stdout
    /// line is delivered with the HOST instant it arrived.
    pub fn spawn(&self, script: &str) -> Result<(Child, mpsc::Receiver<(Instant, String)>)> {
        let mut child = self
            .shell_cmd(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("guest spawn: {script}"))?;
        let stdout = child.stdout.take().expect("piped");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send((Instant::now(), line)).is_err() {
                    break;
                }
            }
        });
        Ok((child, rx))
    }
}

/// Find the interface carrying `mac` in macOS `ifconfig -a` output. macOS
/// prints MACs zero-stripped (`52:55:55:a0:0:1`), hence the parse rather
/// than a string compare.
pub fn iface_with_mac(ifconfig: &str, mac: Mac) -> Option<String> {
    let mut current: Option<&str> = None;
    for line in ifconfig.lines() {
        if !line.starts_with(['\t', ' ']) {
            current = line.split(':').next().filter(|s| !s.is_empty());
            continue;
        }
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("ether ")
            && parse_mac(rest.split_whitespace().next().unwrap_or("")) == Some(mac)
        {
            return current.map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFCONFIG: &str = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 52:55:55:12:34:56
\tinet 192.168.5.15 netmask 0xffffff00 broadcast 192.168.5.255
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 52:55:55:a0:0:1
en2: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 52:55:55:b0:0:1
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 52:55:55:a0:0:1
";

    #[test]
    fn finds_the_nic_by_its_zero_stripped_mac() {
        assert_eq!(iface_with_mac(IFCONFIG, [0x52, 0x55, 0x55, 0xb0, 0, 1]).as_deref(), Some("en2"));
        assert_eq!(iface_with_mac(IFCONFIG, [0x52, 0x55, 0x55, 0xc0, 0, 1]), None);
    }

    /// Should a bridge ever report a member's MAC, the FIRST match must still
    /// be the member NIC, since `ifconfig -a` lists `enN` before `bridgeN`.
    #[test]
    fn a_bridge_sharing_the_member_mac_does_not_shadow_the_member() {
        assert_eq!(iface_with_mac(IFCONFIG, [0x52, 0x55, 0x55, 0xa0, 0, 1]).as_deref(), Some("en1"));
    }
}
