//! Source scans and dependency denylists (architecture.md 7.8, REQ-GUI-070..074).

use std::fs;
use std::path::{Path, PathBuf};

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Remove `//` comments (outside string literals), keeping line structure.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let mut in_str = false;
        let mut escaped = false;
        let mut prev = '\0';
        let mut cut = line.len();
        for (i, c) in line.char_indices() {
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
            } else if c == '"' {
                in_str = true;
            } else if c == '/' && prev == '/' {
                cut = i - 1;
                break;
            }
            prev = c;
        }
        out.push_str(line.get(..cut).unwrap_or(line));
        out.push('\n');
    }
    out
}

/// The part of a file before its first `#[cfg(test)]`.
fn non_test_part(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(i) => src.get(..i).unwrap_or(src),
        None => src,
    }
}

/// True when `needle` occurs in `hay` not preceded by an identifier character.
fn has_token(hay: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(off) = hay.get(from..).and_then(|h| h.find(needle)) {
        let at = from + off;
        let before = hay.get(..at).and_then(|h| h.chars().next_back());
        if !before.is_some_and(is_ident) {
            return true;
        }
        from = at + needle.len();
    }
    false
}

const FORBIDDEN: &[&str] = &[
    "println!",
    "eprintln!",
    "print!",
    "eprint!",
    "dbg!",
    "log::",
    "tracing::",
    "std::net",
    "ToSocketAddrs",
];

/// Forbidden output/logging/network uses in one file's text.
fn scan_forbidden(src: &str) -> Vec<&'static str> {
    let code = strip_comments(src);
    FORBIDDEN
        .iter()
        .copied()
        .filter(|n| has_token(&code, n))
        .collect()
}

/// `egui` / `eframe` named in one file's code.
fn scan_gui_names(src: &str) -> bool {
    let code = strip_comments(src);
    has_token(&code, "egui") || has_token(&code, "eframe")
}

const PANICKY: &[&str] = &[
    ".unwrap()",
    ".expect(",
    "panic!",
    "unreachable!",
    "todo!",
    "unimplemented!",
];

/// Panicking constructs outside the test part of a file.
fn scan_panics(src: &str) -> Vec<&'static str> {
    let code = strip_comments(non_test_part(src));
    PANICKY
        .iter()
        .copied()
        .filter(|n| code.contains(n))
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn all_sources() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    rust_files(&src_dir(), &mut files);
    assert!(files.len() >= 10, "source tree not found");
    files
        .into_iter()
        .map(|p| {
            let t = fs::read_to_string(&p).expect("read source");
            (p, t)
        })
        .collect()
}

fn may_name_gui(p: &Path) -> bool {
    let rel = p.strip_prefix(src_dir()).unwrap_or(p);
    rel == Path::new("app.rs")
        || rel == Path::new("main.rs")
        || rel == Path::new("view.rs")
        || rel.starts_with("view")
}

// ---- scanner self-tests on synthetic input ----

#[test]
fn scanner_flags_planted_forbidden_uses() {
    for bad in [
        "fn f() { println!(\"x\"); }",
        "fn f() { eprintln!(\"x\"); }",
        "fn f() { print!(\"x\"); }",
        "fn f() { eprint!(\"x\"); }",
        "fn f() { dbg!(1); }",
        "fn f() { log::info!(\"x\"); }",
        "fn f() { tracing::warn!(\"x\"); }",
        "use std::net::TcpStream;",
        "use std::net::ToSocketAddrs;",
        "fn f<T: ToSocketAddrs>(_t: T) {}",
    ] {
        assert!(!scan_forbidden(bad).is_empty(), "missed: {bad}");
    }
    // Identifiers that merely contain a name, and comments, are fine.
    for ok in [
        "fn f() { let catalog::x = 1; }",
        "// println!(\"x\") in a comment\nfn f() {}",
        "fn f() { sprint!(1); }",
    ] {
        assert!(scan_forbidden(ok).is_empty(), "false positive: {ok}");
    }
}

#[test]
fn scanner_flags_gui_names_and_panics() {
    assert!(scan_gui_names("use egui::Ui;"));
    assert!(scan_gui_names("fn f() { eframe::run_native(); }"));
    assert!(!scan_gui_names("// egui is only in the view\nfn f() {}"));
    assert!(scan_panics("fn f() { x.unwrap(); }").contains(&".unwrap()"));
    assert!(scan_panics("fn f() { x.expect(\"m\"); }").contains(&".expect("));
    assert!(scan_panics("fn f() { panic!(\"m\"); }").contains(&"panic!"));
    assert!(scan_panics("fn f() { x.unwrap_or(1); }").is_empty());
    // Test code after the cfg(test) marker is exempt.
    assert!(scan_panics("fn f() {}\n#[cfg(test)]\nmod t { fn g() { x.unwrap(); } }").is_empty());
}

// ---- the real tree ----

#[test]
fn real_tree_has_no_forbidden_output_logging_or_network() {
    for (p, t) in all_sources() {
        assert!(
            scan_forbidden(&t).is_empty(),
            "{}: {:?}",
            p.display(),
            scan_forbidden(&t)
        );
    }
}

#[test]
fn real_tree_names_gui_crates_only_in_view_app_main() {
    for (p, t) in all_sources() {
        if !may_name_gui(&p) {
            assert!(!scan_gui_names(&t), "{} names egui/eframe", p.display());
        }
    }
}

#[test]
fn real_tree_has_no_panicking_constructs_outside_tests() {
    for (p, t) in all_sources() {
        assert!(
            scan_panics(&t).is_empty(),
            "{}: {:?}",
            p.display(),
            scan_panics(&t)
        );
    }
}

#[test]
fn crate_roots_forbid_unsafe_and_deny_panicking_lints() {
    for name in ["lib.rs", "main.rs"] {
        let t = fs::read_to_string(src_dir().join(name)).expect("read root");
        assert!(t.starts_with("#![forbid(unsafe_code)]"), "{name}");
        for lint in ["unwrap_used", "expect_used", "panic", "indexing_slicing"] {
            assert!(t.contains(&format!("clippy::{lint}")), "{name}: {lint}");
        }
    }
}

// ---- Cargo.lock denylist and feature check ----

const DENY: &[&str] = &[
    "reqwest",
    "hyper",
    "ureq",
    "isahc",
    "curl",
    "surf",
    "attohttpc",
    "native-tls",
    "rustls",
    "openssl",
    "openssl-sys",
    "tokio",
    "async-std",
    "zbus",
    "ashpd",
    "sentry",
    "opentelemetry",
];

/// (name, dependency names) of each package of a lock file.
fn lock_packages(lock: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let mut name = String::new();
        let mut deps = Vec::new();
        let mut in_deps = false;
        for l in block.lines() {
            let t = l.trim();
            if let Some(n) = t.strip_prefix("name = \"") {
                name = n.trim_end_matches('"').to_owned();
            } else if t.starts_with("dependencies = [") {
                in_deps = true;
            } else if in_deps && t == "]" {
                in_deps = false;
            } else if in_deps {
                let d = t.trim_matches(|c| c == '"' || c == ',');
                deps.push(d.split(' ').next().unwrap_or("").to_owned());
            }
        }
        out.push((name, deps));
    }
    out
}

/// `tokio` appears in the lock only because `wasm-bindgen-futures` (a WebAssembly-only
/// dependency of winit/rfd) enables its `rt` feature; Cargo.lock lists every target. It is
/// tolerated only in exactly that shape: no network or OS-level dependency of its own, and
/// no dependent other than `wasm-bindgen-futures`. See agent-notes/spec-issues.md.
fn tokio_is_the_inert_wasm_only_one(pkgs: &[(String, Vec<String>)]) -> bool {
    let own_ok = pkgs
        .iter()
        .filter(|(n, _)| n == "tokio")
        .all(|(_, d)| d.iter().all(|x| x == "pin-project-lite"));
    let dependents_ok = pkgs
        .iter()
        .filter(|(_, d)| d.iter().any(|x| x == "tokio"))
        .all(|(n, _)| n == "wasm-bindgen-futures");
    own_ok && dependents_ok
}

/// Denied package names present in a lock file's text.
fn denied_in_lock(lock: &str) -> Vec<&'static str> {
    let pkgs = lock_packages(lock);
    DENY.iter()
        .copied()
        .filter(|n| pkgs.iter().any(|(p, _)| p == n))
        .filter(|n| !(*n == "tokio" && tokio_is_the_inert_wasm_only_one(&pkgs)))
        .collect()
}

#[test]
fn denylist_catches_synthetic_lock() {
    let lock = "[[package]]\nname = \"reqwest\"\nversion = \"0.12.0\"\n";
    assert_eq!(denied_in_lock(lock), vec!["reqwest"]);
    for n in DENY.iter().filter(|n| **n != "tokio") {
        assert_eq!(
            denied_in_lock(&format!("[[package]]\nname = \"{n}\"\n")).len(),
            1,
            "{n}"
        );
    }
    // The inert wasm-only tokio is tolerated; any other shape is not.
    let wasm = "[[package]]\nname = \"tokio\"\ndependencies = [\n \"pin-project-lite\",\n]\n\n[[package]]\nname = \"wasm-bindgen-futures\"\ndependencies = [\n \"tokio\",\n]\n";
    assert!(denied_in_lock(wasm).is_empty());
    let with_mio = wasm.replace("\"pin-project-lite\"", "\"mio\"");
    assert_eq!(denied_in_lock(&with_mio), vec!["tokio"]);
    let other = format!("{wasm}\n[[package]]\nname = \"app\"\ndependencies = [\n \"tokio\",\n]\n");
    assert_eq!(denied_in_lock(&other), vec!["tokio"]);
    // A longer name that merely starts with a denied one is not a match.
    assert!(denied_in_lock("[[package]]\nname = \"hyper-util-not\"\n").is_empty());
}

#[test]
fn real_lock_file_has_no_network_crates() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = fs::read_to_string(p).expect("read Cargo.lock");
    assert!(lock.contains("name = \"onlypassword-desktop\""));
    assert_eq!(denied_in_lock(&lock), Vec::<&str>::new());
}

/// Lines of the `[dependencies]` table of a manifest.
fn dependencies_section(toml: &str) -> String {
    let mut inside = false;
    let mut out = String::new();
    for l in toml.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            inside = t == "[dependencies]";
            continue;
        }
        if inside {
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

#[test]
fn dependencies_section_scanner_detects_test_features() {
    let bad = "[dependencies]\nc = { features = [\"insecure-fast-kdf\"] }\n[dev-dependencies]\n";
    assert!(dependencies_section(bad).contains("insecure-fast-kdf"));
    let ok = "[dependencies]\na = \"1\"\n[dev-dependencies]\nc = { features = [\"test-hooks\"] }\n";
    assert!(!dependencies_section(ok).contains("test-hooks"));
}

#[test]
fn desktop_dependencies_never_enable_test_features() {
    let t = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read manifest");
    let deps = dependencies_section(&t);
    assert!(deps.contains("onlypassword-core"));
    assert!(!deps.contains("insecure-fast-kdf"));
    assert!(!deps.contains("test-hooks"));
}
