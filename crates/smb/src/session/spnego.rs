//! Minimal SPNEGO (RFC 4178) wrapper for SMB2 Session Setup.
//!
//! sspi-rs's `Negotiate` SSP produces raw NTLM tokens when Kerberos is
//! unavailable.  SMB2 Session Setup, however, requires the security blob
//! to be a GSSAPI / SPNEGO token (MS-SMB2 §3.2.4.2.3).
//!
//! This module provides lightweight DER helpers to:
//!   * Wrap an NTLM Type-1 in a SPNEGO `NegTokenInit`.
//!   * Wrap an NTLM Type-3 in a SPNEGO `NegTokenResp`.
//!   * Unwrap a server's SPNEGO `NegTokenResp` to extract the inner
//!     NTLM Type-2 challenge.
//!
//! Only the minimum ASN.1/DER subset required by NTLM-over-SPNEGO is
//! implemented.  Full ASN.1 parsing is deliberately avoided.

use crate::Error;

// ── OID constants (DER-encoded, including tag + length) ──────────────

/// SPNEGO mechanism OID  1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// NTLMSSP mechanism OID  1.3.6.1.4.1.311.2.2.10
const NTLMSSP_OID: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];

/// NTLM signature at byte offset 0 of every NTLM message.
const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

// ── DER helpers ──────────────────────────────────────────────────────

fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

/// Build a DER TLV (tag-length-value).
fn der_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + payload.len());
    out.push(tag);
    out.extend(der_encode_length(payload.len()));
    out.extend(payload);
    out
}

/// Read the length field of a DER TLV.
/// Returns `(value_length, bytes_consumed_for_length_field)`.
fn der_read_length(data: &[u8]) -> crate::Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidMessage("DER: empty length field".into()));
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 3 || data.len() < 1 + num_bytes {
            return Err(Error::InvalidMessage("DER: unsupported length encoding".into()));
        }
        let mut val: usize = 0;
        for i in 0..num_bytes {
            val = (val << 8) | data[1 + i] as usize;
        }
        Ok((val, 1 + num_bytes))
    }
}

/// Skip a DER tag byte + length field, returning the total header size
/// and the value length.
///
/// Also validates that the declared value is actually present in `data`,
/// so callers can trust `val_len` without further clamping.  A truncated
/// TLV is rejected up front instead of being silently clipped.
fn der_skip_header(data: &[u8]) -> crate::Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidMessage("DER: unexpected end of data".into()));
    }
    let (val_len, len_bytes) = der_read_length(&data[1..])?;
    let header_len = 1 + len_bytes;
    let total = header_len
        .checked_add(val_len)
        .ok_or_else(|| Error::InvalidMessage("DER: length overflow".into()))?;
    if data.len() < total {
        return Err(Error::InvalidMessage(format!(
            "DER: truncated value (declared {val_len} bytes, have {} after header)",
            data.len().saturating_sub(header_len)
        )));
    }
    Ok((header_len, val_len))
}

// ── Public API ───────────────────────────────────────────────────────

/// Returns `true` if `token` looks like a raw NTLM message (starts with
/// `NTLMSSP\0`).  When `false`, the token is presumably already SPNEGO.
pub fn is_raw_ntlm(token: &[u8]) -> bool {
    token.len() >= NTLMSSP_SIGNATURE.len() && token.starts_with(NTLMSSP_SIGNATURE)
}

/// Wrap an NTLM Type-1 (NEGOTIATE_MESSAGE) in a SPNEGO `NegTokenInit`.
///
/// ```text
/// APPLICATION[0] {
///   OID  1.3.6.1.5.5.2          -- SPNEGO
///   [0] {                        -- NegotiationToken  (CHOICE → NegTokenInit)
///     SEQUENCE {                 -- NegTokenInit
///       [0] SEQUENCE OF { OID NTLMSSP }   -- mechTypes
///       [2] OCTET STRING { <Type-1> }     -- mechToken
///     }
///   }
/// }
/// ```
pub fn wrap_init(ntlm_token: &[u8]) -> Vec<u8> {
    let mech_token = der_tlv(0x04, ntlm_token); // OCTET STRING
    let mech_token_ctx = der_tlv(0xa2, &mech_token); // [2]

    let mech_types_seq = der_tlv(0x30, NTLMSSP_OID); // SEQUENCE OF { OID }
    let mech_types_ctx = der_tlv(0xa0, &mech_types_seq); // [0]

    let mut init_body = Vec::with_capacity(mech_types_ctx.len() + mech_token_ctx.len());
    init_body.extend(&mech_types_ctx);
    init_body.extend(&mech_token_ctx);
    let neg_token_init = der_tlv(0x30, &init_body); // SEQUENCE

    let negotiation_token = der_tlv(0xa0, &neg_token_init); // [0] CHOICE

    let mut app_body = Vec::with_capacity(SPNEGO_OID.len() + negotiation_token.len());
    app_body.extend(SPNEGO_OID);
    app_body.extend(&negotiation_token);
    der_tlv(0x60, &app_body) // APPLICATION[0]
}

/// Wrap an NTLM Type-3 (AUTHENTICATE_MESSAGE) in a SPNEGO `NegTokenResp`.
///
/// ```text
/// [1] {                          -- NegotiationToken  (CHOICE → NegTokenResp)
///   SEQUENCE {
///     [2] OCTET STRING { <Type-3> }   -- responseToken
///   }
/// }
/// ```
pub fn wrap_response(ntlm_token: &[u8]) -> Vec<u8> {
    let response_token = der_tlv(0x04, ntlm_token); // OCTET STRING
    let response_token_ctx = der_tlv(0xa2, &response_token); // [2]
    let neg_token_resp = der_tlv(0x30, &response_token_ctx); // SEQUENCE
    der_tlv(0xa1, &neg_token_resp) // [1] CHOICE
}

/// Wrap an NTLM Type-3 (AUTHENTICATE_MESSAGE) in a SPNEGO `NegTokenResp`
/// with a mechListMIC.
///
/// Per MS-SPNG §3.1.5.1, when the negotiated mechanism's security context
/// is complete, the initiator MUST include the mechListMIC.
///
/// ```text
/// [1] {
///   SEQUENCE {
///     [2] OCTET STRING { <Type-3> }   -- responseToken
///     [3] OCTET STRING { <MIC> }      -- mechListMIC
///   }
/// }
/// ```
pub fn wrap_response_with_mic(ntlm_token: &[u8], mic: &[u8]) -> Vec<u8> {
    let response_token = der_tlv(0x04, ntlm_token); // OCTET STRING
    let response_token_ctx = der_tlv(0xa2, &response_token); // [2]
    let mic_octet = der_tlv(0x04, mic); // OCTET STRING
    let mic_ctx = der_tlv(0xa3, &mic_octet); // [3] mechListMIC
    let mut seq = response_token_ctx;
    seq.extend(mic_ctx);
    let neg_token_resp = der_tlv(0x30, &seq); // SEQUENCE
    der_tlv(0xa1, &neg_token_resp) // [1] CHOICE
}

/// The DER-encoded mechTypeList from the NegTokenInit (only NTLMSSP OID).
///
/// Per MS-SPNG §3.1.5.1, the mechListMIC is computed over the `mechTypes`
/// field of the initial NegTokenInit.  This is the raw `MechTypeList`
/// (SEQUENCE OF MechType) WITHOUT the context tag [0].
///
/// ```text
/// SEQUENCE {
///   OID 1.3.6.1.4.1.311.2.2.10   -- NTLMSSP
/// }
/// ```
pub const MECH_TYPE_LIST_BYTES: &[u8] = &[
    0x30, 0x0C, // SEQUENCE of 12 bytes
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A,
];

/// Same as MECH_TYPE_LIST_BYTES but with the context [0] tag wrapper.
/// Some implementations compute the MIC over the tagged field.
#[allow(dead_code)]
pub const MECH_TYPE_LIST_BYTES_TAGGED: &[u8] = &[
    0xa0, 0x0E, // [0] context tag, length 14
    0x30, 0x0C, // SEQUENCE of 12 bytes
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A,
];

/// Build a minimal SPNEGO NegTokenResp with negState = accept-completed (0).
///
/// Used as the final client acknowledgment when the server sends
/// STATUS_MORE_PROCESSING_REQUIRED with a mechListMIC after the NTLM
/// exchange is complete.  Per RFC 4178 §5, when the preferred mechanism
/// is the common mechanism and optimistic token was used, the response
/// need not include a mechListMIC.
pub fn make_accept_complete() -> Vec<u8> {
    let neg_state = der_tlv(0x0a, &[0x00]); // ENUMERATED: accept-completed
    let neg_state_ctx = der_tlv(0xa0, &neg_state); // [0]
    let neg_token_resp = der_tlv(0x30, &neg_state_ctx); // SEQUENCE
    der_tlv(0xa1, &neg_token_resp) // [1] CHOICE
}

/// Build a SPNEGO NegTokenResp with negState = accept-completed (0) and
/// a mechListMIC computed by the caller.
///
/// Used as the final client acknowledgment when the server sends
/// STATUS_MORE_PROCESSING_REQUIRED with its own mechListMIC.
#[allow(dead_code)]
pub fn make_accept_complete_with_mic(mic: &[u8]) -> Vec<u8> {
    let neg_state = der_tlv(0x0a, &[0x00]); // ENUMERATED: accept-completed
    let neg_state_ctx = der_tlv(0xa0, &neg_state); // [0]
    let mic_octet = der_tlv(0x04, mic); // OCTET STRING
    let mic_ctx = der_tlv(0xa3, &mic_octet); // [3] mechListMIC
    let mut seq = neg_state_ctx;
    seq.extend(mic_ctx);
    let neg_token_resp = der_tlv(0x30, &seq); // SEQUENCE
    der_tlv(0xa1, &neg_token_resp) // [1] CHOICE
}

/// Extract the mechToken from a SPNEGO `NegTokenInit` (APPLICATION[0]).
///
/// This is used to strip sspi-rs's own SPNEGO wrapper so we can re-wrap
/// with a clean, minimal NegTokenInit containing only the NTLMSSP OID.
///
/// Returns the raw mechanism token (NTLM Type-1), or an error if the
/// structure cannot be parsed.
pub fn unwrap_init(gss_token: &[u8]) -> crate::Result<Vec<u8>> {
    if gss_token.is_empty() || gss_token[0] != 0x60 {
        return Err(Error::InvalidMessage(
            format!(
                "SPNEGO: expected APPLICATION[0] (0x60), got 0x{:02x}",
                gss_token.first().copied().unwrap_or(0)
            ),
        ));
    }

    // Skip APPLICATION[0] header.
    let (app_hdr, _) = der_skip_header(gss_token)?;
    let inner = &gss_token[app_hdr..];

    // Skip the SPNEGO OID (should be 06 06 2b 06 01 05 05 02).
    if inner.len() < SPNEGO_OID.len() || &inner[..SPNEGO_OID.len()] != SPNEGO_OID {
        return Err(Error::InvalidMessage("SPNEGO: missing SPNEGO OID in NegTokenInit".into()));
    }
    let after_oid = &inner[SPNEGO_OID.len()..];

    // Skip [0] NegotiationToken wrapper.
    if after_oid.is_empty() || after_oid[0] != 0xa0 {
        return Err(Error::InvalidMessage("SPNEGO: expected [0] in NegTokenInit".into()));
    }
    let (ctx0_hdr, _) = der_skip_header(after_oid)?;
    let neg_token = &after_oid[ctx0_hdr..];

    // Skip SEQUENCE (NegTokenInit body).
    if neg_token.is_empty() || neg_token[0] != 0x30 {
        return Err(Error::InvalidMessage("SPNEGO: expected SEQUENCE in NegTokenInit".into()));
    }
    let (seq_hdr, seq_len) = der_skip_header(neg_token)?;
    let seq_body = &neg_token[seq_hdr..seq_hdr + seq_len];
    let mut pos = 0;

    while pos < seq_len {
        let tag = seq_body[pos];
        let (elem_hdr, elem_len) = der_skip_header(&seq_body[pos..])?;

        if tag == 0xa2 {
            // [2] mechToken — extract the OCTET STRING inside.
            let elem_body = &seq_body[pos + elem_hdr..pos + elem_hdr + elem_len];
            if elem_body.is_empty() || elem_body[0] != 0x04 {
                return Err(Error::InvalidMessage(
                    "SPNEGO: expected OCTET STRING inside mechToken".into(),
                ));
            }
            let (octet_hdr, octet_len) = der_skip_header(elem_body)?;
            return Ok(elem_body[octet_hdr..octet_hdr + octet_len].to_vec());
        }

        pos += elem_hdr + elem_len;
    }

    Err(Error::InvalidMessage(
        "SPNEGO: mechToken ([2]) not found in NegTokenInit".into(),
    ))
}

/// Extract the inner NTLM token from a server's SPNEGO `NegTokenResp`.
///
/// The server sends:
/// ```text
/// [1] {                          -- NegTokenResp
///   SEQUENCE {
///     [0] ENUMERATED { … }       -- negState  (optional)
///     [1] OID { … }              -- supportedMech  (optional)
///     [2] OCTET STRING { <NTLM Type-2> }  -- responseToken
///     [3] OCTET STRING { … }     -- mechListMIC  (optional)
///   }
/// }
/// ```
///
/// If the token is already raw NTLM, it is returned unchanged.
pub fn unwrap_response(gss_token: &[u8]) -> crate::Result<Vec<u8>> {
    // Fast path: already raw NTLM.
    if is_raw_ntlm(gss_token) {
        return Ok(gss_token.to_vec());
    }

    // Expect outer tag [1] (NegTokenResp).
    if gss_token.is_empty() || gss_token[0] != 0xa1 {
        return Err(Error::InvalidMessage(
            format!(
                "SPNEGO: expected NegTokenResp (0xa1), got 0x{:02x}",
                gss_token.first().copied().unwrap_or(0)
            ),
        ));
    }

    let (hdr_size, _) = der_skip_header(gss_token)?;
    let inner = &gss_token[hdr_size..];

    // Inner must be SEQUENCE.
    if inner.is_empty() || inner[0] != 0x30 {
        return Err(Error::InvalidMessage("SPNEGO: expected SEQUENCE inside NegTokenResp".into()));
    }

    let (seq_hdr, seq_len) = der_skip_header(inner)?;
    let seq_body = &inner[seq_hdr..seq_hdr + seq_len];
    let mut pos = 0;

    while pos < seq_len {
        let tag = seq_body[pos];
        let (elem_hdr, elem_len) = der_skip_header(&seq_body[pos..])?;

        if tag == 0xa2 {
            // [2] responseToken — should contain OCTET STRING.
            let elem_body = &seq_body[pos + elem_hdr..pos + elem_hdr + elem_len];
            if elem_body.is_empty() || elem_body[0] != 0x04 {
                return Err(Error::InvalidMessage(
                    "SPNEGO: expected OCTET STRING inside responseToken".into(),
                ));
            }
            let (octet_hdr, octet_len) = der_skip_header(elem_body)?;
            return Ok(elem_body[octet_hdr..octet_hdr + octet_len].to_vec());
        }

        pos += elem_hdr + elem_len;
    }

    Err(Error::InvalidMessage(
        "SPNEGO: responseToken ([2]) not found in NegTokenResp".into(),
    ))
}

// ── Unit tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal NTLM Type-1 stub (just the signature + message type).
    const FAKE_TYPE1: &[u8] = b"NTLMSSP\x00\x01\x00\x00\x00";

    #[test]
    fn is_raw_ntlm_detects_signature() {
        assert!(is_raw_ntlm(FAKE_TYPE1));
        assert!(!is_raw_ntlm(&[0xa1, 0x03, 0x30, 0x01, 0x00]));
        assert!(!is_raw_ntlm(&[]));
    }

    #[test]
    fn wrap_init_produces_valid_der() {
        let wrapped = wrap_init(FAKE_TYPE1);
        // APPLICATION[0] tag
        assert_eq!(wrapped[0], 0x60);
        // Contains SPNEGO OID
        assert!(wrapped.windows(SPNEGO_OID.len()).any(|w| w == SPNEGO_OID));
        // Contains NTLMSSP OID
        assert!(wrapped.windows(NTLMSSP_OID.len()).any(|w| w == NTLMSSP_OID));
        // Contains the original NTLM token
        assert!(wrapped.windows(FAKE_TYPE1.len()).any(|w| w == FAKE_TYPE1));
    }

    #[test]
    fn wrap_response_produces_valid_der() {
        let wrapped = wrap_response(FAKE_TYPE1);
        assert_eq!(wrapped[0], 0xa1);
        assert!(wrapped.windows(FAKE_TYPE1.len()).any(|w| w == FAKE_TYPE1));
    }

    #[test]
    fn unwrap_response_roundtrips() {
        let inner_token = b"NTLMSSP\x00\x02\x00\x00\x00CHALLENGE_DATA_HERE";

        // Manually build a NegTokenResp with [2] responseToken.
        let octet = der_tlv(0x04, inner_token);
        let ctx2 = der_tlv(0xa2, &octet);
        // Also add a dummy [0] negState before the responseToken.
        let neg_state = der_tlv(0xa0, &[0x0a, 0x01, 0x01]); // ENUMERATED accept-incomplete
        let mut seq_body = Vec::new();
        seq_body.extend(&neg_state);
        seq_body.extend(&ctx2);
        let seq = der_tlv(0x30, &seq_body);
        let neg_token_resp = der_tlv(0xa1, &seq);

        let extracted = unwrap_response(&neg_token_resp).unwrap();
        assert_eq!(&extracted, inner_token);
    }

    #[test]
    fn unwrap_response_passes_raw_ntlm_through() {
        let raw = b"NTLMSSP\x00\x02\x00\x00\x00";
        let extracted = unwrap_response(raw).unwrap();
        assert_eq!(&extracted, raw);
    }
}
