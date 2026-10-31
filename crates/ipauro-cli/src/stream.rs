//! `ipauro stream …` — reference client for the binary stream facet
//! (R003-F7, wire spec in [`ipauro_proto::stream`]). Talks to
//! `<control socket>.stream`, never the JSON control socket.

use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use ipauro_proto::stream::{self as wire, Msg, StreamInfo, STREAM_PROTOCOL_VERSION};

use crate::{EXIT_COMMAND_ERR, EXIT_CONNECTION, EXIT_OK, EXIT_VERSION_MISMATCH};

type Conn = (BufReader<UnixStream>, UnixStream);

fn connect(control: &Path, err_out: &mut dyn Write) -> Result<Conn, i32> {
    let path = wire::stream_socket_path(control);
    let s = UnixStream::connect(&path).map_err(|e| {
        let _ = writeln!(err_out, "cannot connect to {}: {e}", path.display());
        EXIT_CONNECTION
    })?;
    let mut w = s.try_clone().map_err(|_| EXIT_CONNECTION)?;
    let mut r = BufReader::new(s);
    let client = format!("ipauro-cli {}", env!("CARGO_PKG_VERSION"));
    wire::write_msg(&mut w, &Msg::Hello { version: STREAM_PROTOCOL_VERSION, client }).map_err(|_| EXIT_CONNECTION)?;
    match wire::read_msg(&mut r) {
        Ok(Some(Msg::HelloAck { accepted: true, .. })) => Ok((r, w)),
        Ok(Some(Msg::HelloAck { version, .. })) => {
            let _ = writeln!(err_out, "server speaks stream v{version}, client v{STREAM_PROTOCOL_VERSION}");
            Err(EXIT_VERSION_MISMATCH)
        }
        other => {
            let _ = writeln!(err_out, "bad handshake: {other:?}");
            Err(EXIT_CONNECTION)
        }
    }
}

fn describe(id: u32, i: &StreamInfo) -> String {
    let d = &i.descriptor;
    let proto = if d.protocol.is_empty() { "-" } else { &d.protocol };
    let mut s = format!(
        "{id}\t{}\t{proto}\t{:?}\t{}ch {:?} @ {} Hz\t{:?}",
        d.name, d.payload, d.channels, d.sample_format, d.nominal_rate_hz, d.clock
    );
    if i.rate_mismatch() {
        s.push_str(&format!("\tRATE MISMATCH (mesh {} Hz)", i.mesh_rate_hz));
    }
    s
}

/// `stream list`.
pub fn list(control: &Path, out: &mut dyn Write, err_out: &mut dyn Write) -> i32 {
    let (mut r, mut w) = match connect(control, err_out) {
        Ok(c) => c,
        Err(code) => return code,
    };
    if wire::write_msg(&mut w, &Msg::List).is_err() {
        return EXIT_CONNECTION;
    }
    match wire::read_msg(&mut r) {
        Ok(Some(Msg::StreamList { streams })) => {
            for (id, info) in &streams {
                let _ = writeln!(out, "{}", describe(*id, info));
            }
            if streams.is_empty() {
                let _ = writeln!(out, "no streams");
            }
            EXIT_OK
        }
        other => {
            let _ = writeln!(err_out, "unexpected reply: {other:?}");
            EXIT_CONNECTION
        }
    }
}

/// `stream tap <id>`: subscribe and count frames/overruns until the stream
/// ends, the connection drops, or `limit` Data frames arrived.
pub fn tap(control: &Path, id: u32, limit: Option<u64>, out: &mut dyn Write, err_out: &mut dyn Write) -> i32 {
    let (mut r, mut w) = match connect(control, err_out) {
        Ok(c) => c,
        Err(code) => return code,
    };
    if wire::write_msg(&mut w, &Msg::Subscribe { stream: id, queue_depth: 0 }).is_err() {
        return EXIT_CONNECTION;
    }
    let (mut frames, mut overrun, mut last_seq) = (0u64, 0u64, None);
    loop {
        match wire::read_msg(&mut r) {
            Ok(Some(Msg::Subscribed { stream, info })) => {
                let _ = writeln!(out, "tapping {}", describe(stream, &info));
            }
            Ok(Some(Msg::Data { seq, .. })) => {
                frames += 1;
                last_seq = Some(seq);
                if limit.is_some_and(|l| frames >= l) {
                    break;
                }
            }
            Ok(Some(Msg::Overrun { dropped_total, .. })) => overrun = dropped_total,
            Ok(Some(Msg::StreamEnded { .. })) | Ok(None) => break,
            Ok(Some(Msg::Error { code, message })) => {
                let _ = writeln!(err_out, "error {code}: {message}");
                return EXIT_COMMAND_ERR;
            }
            Ok(Some(other)) => {
                let _ = writeln!(err_out, "unexpected message: {other:?}");
                return EXIT_CONNECTION;
            }
            Err(e) => {
                let _ = writeln!(err_out, "stream read failed: {e}");
                return EXIT_CONNECTION;
            }
        }
    }
    let last = last_seq.map_or("-".to_string(), |s| s.to_string());
    let _ = writeln!(out, "frames={frames} overrun={overrun} last_seq={last}");
    EXIT_OK
}
