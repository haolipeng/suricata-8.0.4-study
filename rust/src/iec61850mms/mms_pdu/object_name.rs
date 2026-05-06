//! MMS ObjectName parsing.

use crate::iec61850mms::ber::{parse_ber_string, parse_ber_tlv, MAX_BER_DEPTH};
use crate::iec61850mms::mms_types::ObjectNameRef;

/// Parse an ObjectName CHOICE, supporting all three variants.
pub(super) fn parse_object_name(content: &[u8], depth: usize) -> Option<ObjectNameRef> {
    if depth > MAX_BER_DEPTH {
        return None;
    }
    if let Ok((tag_byte, _, _, inner, _)) = parse_ber_tlv(content) {
        match tag_byte {
            0x80 => Some(ObjectNameRef::VmdSpecific(parse_ber_string(inner))),
            0xA1 => {
                let ds = parse_domain_specific_sequence(inner, depth + 1)?;
                Some(ObjectNameRef::DomainSpecific {
                    domain_id: ds.0,
                    item_id: ds.1,
                })
            }
            0x82 => Some(ObjectNameRef::AaSpecific(parse_ber_string(inner))),
            _ => None,
        }
    } else {
        None
    }
}

/// Parse a domain-specific SEQUENCE { domainId, itemId }.
fn parse_domain_specific_sequence(content: &[u8], depth: usize) -> Option<(String, String)> {
    if depth > MAX_BER_DEPTH {
        return None;
    }
    let (_, _, _, domain_bytes, rem) = parse_ber_tlv(content).ok()?;
    let domain_id = parse_ber_string(domain_bytes);
    let (_, _, _, item_bytes, _) = parse_ber_tlv(rem).ok()?;
    let item_id = parse_ber_string(item_bytes);
    Some((domain_id, item_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_object_name_all_variants_contract() {
        assert_eq!(
            parse_object_name(&[0x80, 0x06, b'G', b'l', b'o', b'b', b'a', b'l'], 0),
            Some(ObjectNameRef::VmdSpecific("Global".to_string()))
        );

        assert_eq!(
            parse_object_name(
                &[
                    0xA1, 0x0B, // domain-specific
                    0x1A, 0x04, b'L', b'L', b'N', b'0', 0x1A, 0x03, b'M', b'o', b'd',
                ],
                0,
            ),
            Some(ObjectNameRef::DomainSpecific {
                domain_id: "LLN0".to_string(),
                item_id: "Mod".to_string(),
            })
        );

        assert_eq!(
            parse_object_name(&[0x82, 0x05, b'A', b'a', b'V', b'a', b'r'], 0),
            Some(ObjectNameRef::AaSpecific("AaVar".to_string()))
        );

        assert_eq!(
            parse_object_name(&[0xA1, 0x06, 0x1A, 0x04, b'L', b'L', b'N', b'0'], 0),
            None,
            "domain-specific ObjectName needs both domainId and itemId"
        );
    }
}
