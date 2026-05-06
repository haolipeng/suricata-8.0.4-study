//! MMS VariableAccessSpecification parsing.

use super::object_name::parse_object_name;
use crate::iec61850mms::ber::{parse_ber_tlv, MAX_BER_DEPTH};
use crate::iec61850mms::mms_types::ObjectNameRef;

/// Maximum number of variable specifications to parse from a single request.
const MAX_VARIABLE_SPECS: usize = super::MAX_VARIABLE_SPECS;

/// Extract domain-specific object references from a Read/Write request.
/// The variable access specification in MMS uses nested constructed tags.
pub(super) fn parse_variable_access_specification(
    content: &[u8], depth: usize,
) -> Vec<ObjectNameRef> {
    let mut specs = Vec::new();
    if depth > MAX_BER_DEPTH {
        return specs;
    }

    if let Ok((tag_byte, _, _, inner, _)) = parse_ber_tlv(content) {
        if tag_byte == 0xA0 {
            let mut pos = inner;
            while !pos.is_empty() && specs.len() < MAX_VARIABLE_SPECS {
                if let Ok((_, _, _, seq_content, rem)) = parse_ber_tlv(pos) {
                    if let Some(name) = extract_object_name_from_var_spec(seq_content, depth + 1) {
                        specs.push(name);
                    }
                    pos = rem;
                } else {
                    break;
                }
            }
        }
    }

    specs
}

/// Extract an ObjectNameRef from a VariableSpecification element.
fn extract_object_name_from_var_spec(content: &[u8], depth: usize) -> Option<ObjectNameRef> {
    if depth > MAX_BER_DEPTH {
        return None;
    }
    if let Ok((tag_byte, _, _, name_content, _)) = parse_ber_tlv(content) {
        if tag_byte == 0xA0 {
            return parse_object_name(name_content, depth + 1);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_variable_access_specification_mixed_object_names_contract() {
        let input = &[
            0xA0, 0x2C, // listOfVariable
            0x30, 0x0C, // variable specification 1
            0xA0, 0x0A, // name
            0x80, 0x08, b'G', b'l', b'o', b'b', b'a', b'l', b'0', b'1', 0x30,
            0x13, // variable specification 2
            0xA0, 0x11, // name
            0xA1, 0x0F, // domain-specific
            0x1A, 0x07, b'I', b'E', b'D', b'1', b'L', b'D', b'0', 0x1A, 0x04, b'M', b'o', b'd',
            b'e', 0x30, 0x07, // variable specification 3
            0xA0, 0x05, // name
            0x82, 0x03, b'A', b'A', b'1',
        ];

        let specs = parse_variable_access_specification(input, 0);
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0], ObjectNameRef::VmdSpecific("Global01".to_string()));
        assert_eq!(
            specs[1],
            ObjectNameRef::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "Mode".to_string(),
            }
        );
        assert_eq!(specs[2], ObjectNameRef::AaSpecific("AA1".to_string()));
    }
}
