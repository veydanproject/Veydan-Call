//! The README says what the node does: its table of settings names every
//! setting of the node, and the rows a volunteer acts on say what the code
//! does.

const README: &str = include_str!("../../../README.md");
const MAIN: &str = include_str!("../src/main.rs");

/// The row of the settings table for `name`.
fn row(name: &str) -> &'static str {
    let cell = format!("| `{name}` |");
    README.lines().find(|l| l.starts_with(&cell)).unwrap_or_else(|| panic!("no row for {name} in the settings table"))
}

/// Every `VCALL_*` the node reads is a row of the table, but for the ones
/// that are not settings of the node: a tool's key, a switch for tests,
/// and one not used yet.
#[test]
fn every_setting_of_the_node_is_in_the_table() {
    let not_settings = ["VCALL_ACCESS_KEY", "VCALL_UNSAFE_RELAY_TO_PRIVATE", "VCALL_ISSUERS"];
    let mut names: Vec<&str> = MAIN.split("env = \"").skip(1).filter_map(|rest| rest.split('"').next()).filter(|n| n.starts_with("VCALL_")).collect();
    names.sort_unstable();
    names.dedup();
    assert!(names.len() > 30, "the settings were not found in main.rs");
    for name in names {
        if not_settings.contains(&name) {
            continue;
        }
        row(name);
    }
}

/// `VCALL_DATA` holds more than the key: the devices a private node let in
/// and the registry's list, which a volume and a backup must keep.
#[test]
fn the_data_row_names_the_files_the_node_keeps() {
    let data = row("VCALL_DATA");
    for file in ["devices.json", "registry-nodes.json", "key", "TURN secret"] {
        assert!(data.contains(file), "the VCALL_DATA row does not name {file}: {data}");
    }
}

/// An unset registry means no list, not a file: the row and the doc
/// comment of `--registry` say what each cascade mode does without one.
#[test]
fn the_registry_row_says_what_unset_means() {
    let registry = row("VCALL_REGISTRY");
    assert!(!registry.contains("trust the file"), "{registry}");
    for word in ["unlisted", "quota", "`registry`", "file"] {
        assert!(registry.contains(word), "the VCALL_REGISTRY row does not say {word}: {registry}");
    }
    let before: Vec<&str> = MAIN.lines().take_while(|l| !l.contains("env = \"VCALL_REGISTRY\"")).collect();
    let comment: String = before.iter().rev().take(4).map(|l| l.trim().trim_start_matches("///")).collect::<Vec<_>>().join(" ");
    assert!(!comment.contains("trust the file"), "{comment}");
    assert!(comment.contains("unlisted") && comment.contains("quota") && comment.contains("file"), "{comment}");
}
