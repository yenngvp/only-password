//! Shared test helper: loads `spec/vectors/*.json` via CARGO_MANIFEST_DIR (REQ-BLD-002).

use std::path::Path;

pub fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    let nib = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("bad hex digit"),
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| nib(p[0]) << 4 | nib(p[1]))
        .collect()
}

pub fn try_load_vectors(name: &str) -> Result<Vec<serde_json::Value>, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(name);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{name}: {e}"))?;
    let doc: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let vs = doc["vectors"].as_array().cloned().unwrap_or_default();
    if vs.is_empty() {
        return Err(format!("{name}: no vectors"));
    }
    Ok(vs)
}

/// Panics (fails the test) if the file is missing or has no vectors.
pub fn load_vectors(name: &str) -> Vec<serde_json::Value> {
    try_load_vectors(name).unwrap_or_else(|e| panic!("{e}"))
}

pub fn field(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex_decode(
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("missing field {key}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_error() {
        assert!(try_load_vectors("does-not-exist.json").is_err());
    }

    #[test]
    #[should_panic]
    fn load_panics_on_missing_file() {
        load_vectors("does-not-exist.json");
    }

    #[test]
    fn empty_vector_list_is_error() {
        // README.md exists but is not JSON; a JSON file with no "vectors" key must also fail.
        assert!(try_load_vectors("README.md").is_err());
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_decode("00ffA1"), vec![0, 255, 161]);
    }
}
