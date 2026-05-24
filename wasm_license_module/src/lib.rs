// Author: X-3306
// Project: https://github.com/X-3306/Project-Onyx

use core::ptr;
use core::slice;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "host")]
extern "C" {
    #[link_name = "get_fingerprint_ptr"]
    fn host_get_fingerprint_ptr() -> u32;

    #[link_name = "get_fingerprint_len"]
    fn host_get_fingerprint_len() -> u32;

    #[link_name = "get_status_ptr"]
    fn host_get_status_ptr() -> u32;

    #[link_name = "get_status_len"]
    fn host_get_status_len() -> u32;

    #[link_name = "get_timestamp_ptr"]
    fn host_get_timestamp_ptr() -> u32;

    #[link_name = "get_timestamp_len"]
    fn host_get_timestamp_len() -> u32;

    #[link_name = "submit_json"]
    fn host_submit_json(ptr: u32, len: u32);

    #[link_name = "post_teams_json"]
    fn host_post_teams_json(ptr: u32, len: u32) -> u32;
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_get_fingerprint_ptr() -> u32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_get_fingerprint_len() -> u32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_get_status_ptr() -> u32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_get_status_len() -> u32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_get_timestamp_ptr() -> u32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_get_timestamp_len() -> u32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_submit_json(_ptr: u32, _len: u32) {}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_post_teams_json(_ptr: u32, _len: u32) -> u32 {
    0
}

const MAX_HOST_STRING_LEN: u32 = 16 * 1024;

#[no_mangle]
pub extern "C" fn run() {
    let mut fingerprint = unsafe {
        read_host_bytes(
            host_get_fingerprint_ptr(),
            host_get_fingerprint_len(),
        )
    };
    let mut status = unsafe {
        read_host_bytes(
            host_get_status_ptr(),
            host_get_status_len(),
        )
    };
    let mut timestamp = unsafe {
        read_host_bytes(
            host_get_timestamp_ptr(),
            host_get_timestamp_len(),
        )
    };

    let mut payload = build_license_payload(&fingerprint, &status, &timestamp);

    unsafe {
        host_submit_json(payload.as_ptr() as u32, payload.len() as u32);
        let _ = host_post_teams_json(payload.as_ptr() as u32, payload.len() as u32);
    }

    secure_zero(&mut payload);
    secure_zero(&mut fingerprint);
    secure_zero(&mut status);
    secure_zero(&mut timestamp);
}

unsafe fn read_host_bytes(ptr: u32, len: u32) -> Vec<u8> {
    if ptr == 0 || len == 0 || len > MAX_HOST_STRING_LEN {
        return Vec::new();
    }

    let src = ptr as usize as *const u8;
    slice::from_raw_parts(src, len as usize).to_vec()
}

fn build_license_payload(fingerprint: &[u8], status: &[u8], timestamp: &[u8]) -> Vec<u8> {
    let decision = if status == b"alive_and_secure" {
        b"allow".as_slice()
    } else {
        b"review".as_slice()
    };

    let mut out = Vec::with_capacity(
        fingerprint.len()
            .saturating_add(status.len())
            .saturating_add(timestamp.len())
            .saturating_add(192),
    );

    out.extend_from_slice(br#"{"schema_version":1"#);
    out.extend_from_slice(br#","event":"license_heartbeat""#);
    out.extend_from_slice(br#","source":"wasm_license_module""#);
    out.extend_from_slice(br#","decision":""#);
    push_json_escaped(&mut out, decision);
    out.extend_from_slice(br#"""#);
    out.extend_from_slice(br#","status":""#);
    push_json_escaped(&mut out, status);
    out.extend_from_slice(br#"""#);
    out.extend_from_slice(br#","timestamp":""#);
    push_json_escaped(&mut out, timestamp);
    out.extend_from_slice(br#"""#);
    out.extend_from_slice(br#","fingerprint":""#);
    push_json_escaped(&mut out, fingerprint);
    out.extend_from_slice(br#""}"#);

    out
}

fn push_json_escaped(out: &mut Vec<u8>, input: &[u8]) {
    for &byte in input {
        match byte {
            b'"' => out.extend_from_slice(br#"\""#),
            b'\\' => out.extend_from_slice(br#"\\"#),
            b'\n' => out.extend_from_slice(br#"\n"#),
            b'\r' => out.extend_from_slice(br#"\r"#),
            b'\t' => out.extend_from_slice(br#"\t"#),
            0x08 => out.extend_from_slice(br#"\b"#),
            0x0c => out.extend_from_slice(br#"\f"#),
            0x00..=0x1f => push_json_u00(out, byte),
            _ => out.push(byte),
        }
    }
}

fn push_json_u00(out: &mut Vec<u8>, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(br#"\u00"#);
    out.push(HEX[(byte >> 4) as usize]);
    out.push(HEX[(byte & 0x0f) as usize]);
}

fn secure_zero(buf: &mut [u8]) {
    for byte in buf {
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_contains_expected_fields_and_decision() {
        let payload = build_license_payload(
            b"abc123",
            b"alive_and_secure",
            b"2026-05-16T12:00:00Z",
        );
        let text = String::from_utf8(payload).unwrap();

        assert!(text.contains(r#""schema_version":1"#));
        assert!(text.contains(r#""event":"license_heartbeat""#));
        assert!(text.contains(r#""source":"wasm_license_module""#));
        assert!(text.contains(r#""decision":"allow""#));
        assert!(text.contains(r#""status":"alive_and_secure""#));
        assert!(text.contains(r#""timestamp":"2026-05-16T12:00:00Z""#));
        assert!(text.contains(r#""fingerprint":"abc123""#));
    }

    #[test]
    fn payload_escapes_json_strings() {
        let payload = build_license_payload(
            br#"aa"bb\cc"#,
            b"needs\nreview",
            b"2026-05-16T12:00:00Z",
        );
        let text = String::from_utf8(payload).unwrap();

        assert!(text.contains(r#""decision":"review""#));
        assert!(text.contains(r#""status":"needs\nreview""#));
        assert!(text.contains(r#""fingerprint":"aa\"bb\\cc""#));
    }

    #[test]
    fn secure_zero_overwrites_buffer() {
        let mut secret = b"very secret value".to_vec();
        secure_zero(&mut secret);

        assert!(secret.iter().all(|&b| b == 0));
    }
}
