//! Reading macOS's Local Network (multicast) grant registry.
//!
//! The behavioural half of this tool (`check`) answers "did traffic actually
//! flow here". This module answers the complementary question the RUNBOOK's
//! matrix also needs: **what decision has the system recorded** for a given
//! code identity. That matters because a grant or denial persists silently —
//! a context can come back open only because someone approved it months ago,
//! and a context can come back shut with no prompt ever shown.
//!
//! The registry lives at [`REGISTRY_PATH`], is world-readable, and is an
//! `NSKeyedArchiver` archive: a top-level `$objects` array where every value
//! is either a leaf (string, bool) or a dict whose fields are `CF$UID`
//! indices back into that same array. Records describing an app's local-network
//! posture carry:
//!
//! * `MulticastPreferenceSet` — whether an explicit decision exists,
//! * `DenyMulticast` — the decision itself (`true` = denied),
//! * `SigningIdentifier` / `Path` — UID references naming the app.
//!
//! Verified empirically on macOS 26.5.1 (R002-T8). Two observations that the
//! field names do not make obvious, and that the matrix depends on:
//!
//! * **`unset` is not `denied`.** The overwhelming majority of entries have no
//!   recorded decision and their traffic flows normally; absence of a decision
//!   means the system has not been told otherwise, not that access is refused.
//! * **A launchd job with `AssociatedBundleIdentifiers` is filed under the
//!   associated bundle id**, not under its executable's own signing
//!   identifier. A bare executable is filed under its signing identifier plus
//!   its path.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use plist::Value;

/// Where macOS keeps the local-network posture for every app it has seen.
pub const REGISTRY_PATH: &str = "/Library/Preferences/com.apple.networkextension.plist";

/// What the system has recorded about one code identity's multicast access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Code-signing identifier, or the bundle id for an associated launchd job.
    pub identifier: Option<String>,
    /// Executable path, present for bare (non-bundle-associated) executables.
    pub path: Option<String>,
    /// Whether an explicit decision has been recorded at all.
    pub decided: bool,
    /// The recorded decision. Only meaningful when `decided`.
    pub denied: bool,
}

impl Grant {
    /// One-word decision for display. `unset` means no explicit decision has
    /// been recorded — which in practice behaves as allowed, not denied.
    pub fn decision(&self) -> &'static str {
        match (self.decided, self.denied) {
            (false, _) => "unset",
            (true, true) => "DENIED",
            (true, false) => "allowed",
        }
    }

    /// True when this record matches a case-insensitive substring of either
    /// the identifier or the path.
    pub fn matches(&self, needle: &str) -> bool {
        let needle = needle.to_lowercase();
        let hit = |field: &Option<String>| {
            field.as_deref().is_some_and(|v| v.to_lowercase().contains(&needle))
        };
        hit(&self.identifier) || hit(&self.path)
    }

    /// Display name: the identifier if there is one, else the path.
    pub fn name(&self) -> &str {
        self.identifier.as_deref().or(self.path.as_deref()).unwrap_or("<unnamed>")
    }
}

/// Read and parse the system registry.
pub fn load() -> Result<Vec<Grant>> {
    load_from(Path::new(REGISTRY_PATH))
}

/// Read and parse a registry archive from an explicit path (test seam).
pub fn load_from(path: &Path) -> Result<Vec<Grant>> {
    let value = Value::from_file(path)
        .with_context(|| format!("reading local-network registry at {}", path.display()))?;
    parse(&value)
}

/// Extract every multicast-posture record from an `NSKeyedArchiver` archive.
///
/// Pure over an already-parsed archive so the keyed-archive walk — the part
/// that is easy to get subtly wrong — is unit-testable without the real
/// system file, which differs per machine and is not checked in.
pub fn parse(archive: &Value) -> Result<Vec<Grant>> {
    let objects = archive
        .as_dictionary()
        .and_then(|d| d.get("$objects"))
        .and_then(Value::as_array)
        .context("not an NSKeyedArchiver archive: no $objects array")?;

    // Resolve a `CF$UID` reference into $objects, keeping only string leaves.
    // UID 0 is the archive's `$null` sentinel and means "field absent".
    let deref = |field: Option<&Value>| -> Option<String> {
        let index = match field? {
            Value::Uid(uid) => uid.get() as usize,
            Value::Integer(i) => i.as_unsigned()? as usize,
            _ => return None,
        };
        if index == 0 {
            return None;
        }
        objects.get(index)?.as_string().map(str::to_owned)
    };

    let mut grants: Vec<Grant> = objects
        .iter()
        .filter_map(Value::as_dictionary)
        .filter(|record| record.contains_key("MulticastPreferenceSet"))
        .map(|record| Grant {
            identifier: deref(record.get("SigningIdentifier")),
            path: deref(record.get("Path")),
            decided: record
                .get("MulticastPreferenceSet")
                .and_then(Value::as_boolean)
                .unwrap_or(false),
            denied: record.get("DenyMulticast").and_then(Value::as_boolean).unwrap_or(false),
        })
        // A record naming neither an identifier nor a path describes no app we
        // can report on (template/default entries).
        .filter(|g| g.identifier.is_some() || g.path.is_some())
        .collect();

    grants.sort_by(|a, b| {
        a.name().to_lowercase().cmp(&b.name().to_lowercase()).then_with(|| a.path.cmp(&b.path))
    });
    Ok(grants)
}

/// Count of each decision, for the summary line.
pub fn tally(grants: &[Grant]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for grant in grants {
        *counts.entry(grant.decision()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::{Dictionary, Uid};

    /// Build a minimal archive in the shape the real file uses: an $objects
    /// array whose record dicts reference string leaves by CF$UID index.
    fn archive(records: Vec<(Option<usize>, Option<usize>, bool, bool)>, leaves: &[&str]) -> Value {
        let mut objects = vec![Value::String("$null".into())];
        for leaf in leaves {
            objects.push(Value::String((*leaf).to_string()));
        }
        for (ident, path, decided, denied) in records {
            let mut record = Dictionary::new();
            record.insert("MulticastPreferenceSet".into(), Value::Boolean(decided));
            record.insert("DenyMulticast".into(), Value::Boolean(denied));
            record.insert(
                "SigningIdentifier".into(),
                Value::Uid(Uid::new(ident.unwrap_or(0) as u64)),
            );
            record.insert("Path".into(), Value::Uid(Uid::new(path.unwrap_or(0) as u64)));
            objects.push(Value::Dictionary(record));
        }
        let mut root = Dictionary::new();
        root.insert("$objects".into(), Value::Array(objects));
        Value::Dictionary(root)
    }

    #[test]
    fn resolves_identifier_and_path_through_uid_references() {
        let v = archive(vec![(Some(1), Some(2), true, false)], &["io.example.app", "/tmp/app"]);
        let grants = parse(&v).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].identifier.as_deref(), Some("io.example.app"));
        assert_eq!(grants[0].path.as_deref(), Some("/tmp/app"));
    }

    #[test]
    fn uid_zero_is_the_null_sentinel_not_an_index() {
        // A bundle-associated job has no Path; that field points at $null.
        let v = archive(vec![(Some(1), None, false, false)], &["io.example.bundle"]);
        let grants = parse(&v).unwrap();
        assert_eq!(grants[0].path, None);
        assert_eq!(grants[0].identifier.as_deref(), Some("io.example.bundle"));
    }

    #[test]
    fn decision_words_distinguish_unset_from_denied() {
        let v = archive(
            vec![
                (Some(1), None, false, false),
                (Some(2), None, true, false),
                (Some(3), None, true, true),
            ],
            &["a-unset", "b-allowed", "c-denied"],
        );
        let grants = parse(&v).unwrap();
        assert_eq!(grants[0].decision(), "unset");
        assert_eq!(grants[1].decision(), "allowed");
        assert_eq!(grants[2].decision(), "DENIED");
    }

    #[test]
    fn an_unset_record_is_not_reported_as_denied() {
        // The trap this module exists to avoid: DenyMulticast defaults to
        // false and MulticastPreferenceSet=false means "no decision", so a
        // reader that looked only at DenyMulticast would call every untouched
        // app "allowed" and every reader of the raw field would be misled.
        let v = archive(vec![(Some(1), None, false, true)], &["weird"]);
        let grants = parse(&v).unwrap();
        assert_eq!(grants[0].decision(), "unset");
    }

    #[test]
    fn records_naming_nothing_are_dropped() {
        let v = archive(vec![(None, None, true, false)], &[]);
        assert!(parse(&v).unwrap().is_empty());
    }

    #[test]
    fn dicts_without_the_multicast_field_are_not_records() {
        let mut unrelated = Dictionary::new();
        unrelated.insert("SomethingElse".into(), Value::Boolean(true));
        let mut root = Dictionary::new();
        root.insert(
            "$objects".into(),
            Value::Array(vec![Value::String("$null".into()), Value::Dictionary(unrelated)]),
        );
        assert!(parse(&Value::Dictionary(root)).unwrap().is_empty());
    }

    #[test]
    fn rejects_input_that_is_not_a_keyed_archive() {
        let err = parse(&Value::String("nope".into())).unwrap_err();
        assert!(err.to_string().contains("$objects"));
    }

    #[test]
    fn matching_is_case_insensitive_across_identifier_and_path() {
        let v =
            archive(vec![(Some(1), Some(2), true, false)], &["io.IPAuRo.core", "/Applications/X"]);
        let grant = &parse(&v).unwrap()[0];
        assert!(grant.matches("ipauro"));
        assert!(grant.matches("applications"));
        assert!(!grant.matches("zzz"));
    }

    #[test]
    fn results_are_sorted_by_name_case_insensitively() {
        let v = archive(
            vec![
                (Some(1), None, false, false),
                (Some(2), None, false, false),
                (Some(3), None, false, false),
            ],
            &["Zebra", "apple", "Mango"],
        );
        let grants = parse(&v).unwrap();
        let names: Vec<&str> = grants.iter().map(Grant::name).collect();
        assert_eq!(names, ["apple", "Mango", "Zebra"]);
    }

    #[test]
    fn tally_counts_each_decision() {
        let v = archive(
            vec![
                (Some(1), None, false, false),
                (Some(2), None, true, false),
                (Some(3), None, true, true),
                (Some(4), None, true, true),
            ],
            &["a", "b", "c", "d"],
        );
        let counts = tally(&parse(&v).unwrap());
        assert_eq!(counts.get("unset"), Some(&1));
        assert_eq!(counts.get("allowed"), Some(&1));
        assert_eq!(counts.get("DENIED"), Some(&2));
    }
}
