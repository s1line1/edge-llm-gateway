//! Package-local architecture guards for boundaries that are easy to regress.

use std::fs;
use std::path::{Path, PathBuf};

fn source_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(source_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

fn assert_no_imports(dir: &str, forbidden: &[&str]) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(dir);
    for file in source_files(&root) {
        let text = fs::read_to_string(&file).unwrap();
        let production = text
            .lines()
            .take_while(|line| !line.trim_start().starts_with("#[cfg(test)]"))
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in forbidden {
            assert!(
                !production.contains(needle),
                "{} must not import `{needle}`; keep the boundary in the adapter/composition layer",
                file.display()
            );
        }
    }
}

#[test]
fn tunnel_does_not_depend_on_persistence_or_http() {
    assert_no_imports("tunnel", &["crate::storage", "crate::http"]);
}

#[test]
fn proxy_does_not_depend_on_pki() {
    assert_no_imports("proxy", &["crate::pki"]);
}

#[test]
fn credentials_do_not_depend_on_http() {
    assert_no_imports("pki", &["crate::http", "axum::"]);
}

#[test]
fn access_does_not_depend_on_http_adapters() {
    assert_no_imports("access", &["crate::http"]);
}

#[test]
fn protocol_crate_does_not_depend_on_app_crates() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("proto/src");
    for file in source_files(&root) {
        let text = fs::read_to_string(&file).unwrap();
        let production = text
            .lines()
            .take_while(|line| !line.trim_start().starts_with("#[cfg(test)]"))
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in ["gateway::", "agent::"] {
            assert!(
                !production.contains(needle),
                "{} must not depend on `{needle}`",
                file.display()
            );
        }
    }
}
