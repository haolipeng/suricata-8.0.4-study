//! MMS Data and AccessResult parsing.

use super::tags::data_tag_name;
use crate::iec61850mms::ber::{
    parse_ber_integer, parse_ber_signed_integer, parse_ber_string, parse_ber_tlv, MAX_BER_DEPTH,
};
use crate::iec61850mms::mms_types::MmsAccessResult;

/// Maximum number of variable specifications to parse from a single request.
const MAX_VARIABLE_SPECS: usize = super::MAX_VARIABLE_SPECS;

/// Parse a list of MMS Data elements with shallow interpretation.
/// Used by both Write request (listOfData) and Read response (listOfAccessResult success items).
pub(super) fn parse_data_list(content: &[u8], depth: usize) -> Vec<MmsAccessResult> {
    let mut results = Vec::new();
    if depth > MAX_BER_DEPTH {
        return results;
    }
    let mut pos = content;
    while !pos.is_empty() && results.len() < MAX_VARIABLE_SPECS {
        if let Ok((item_tag, _, item_tag_num, item_inner, item_rem)) = parse_ber_tlv(pos) {
            results.push(parse_data_element(item_tag, item_tag_num, item_inner));
            pos = item_rem;
        } else {
            break;
        }
    }
    results
}

/// Parse a single MMS Data element into an MmsAccessResult (shallow).
pub(super) fn parse_data_element(
    item_tag: u8, item_tag_num: u32, item_inner: &[u8],
) -> MmsAccessResult {
    let type_name = data_tag_name(item_tag_num).map(|s| s.to_string());

    let value = if item_tag == 0xA1 || item_tag == 0xA2 {
        // array [1] / structure [2]: count members
        let mut count = 0u32;
        let mut cpos = item_inner;
        while !cpos.is_empty() {
            if let Ok((_, _, _, _, crem)) = parse_ber_tlv(cpos) {
                count += 1;
                cpos = crem;
            } else {
                break;
            }
        }
        Some(format!("{} items", count))
    } else if item_tag == 0x83 {
        // [3] boolean
        if !item_inner.is_empty() {
            Some(if item_inner[0] != 0 { "true" } else { "false" }.to_string())
        } else {
            None
        }
    } else if item_tag == 0x85 {
        // [5] integer (signed)
        parse_ber_signed_integer(item_inner)
            .map(|v| v.to_string())
            .ok()
    } else if item_tag == 0x86 {
        // [6] unsigned
        parse_ber_integer(item_inner).map(|v| v.to_string()).ok()
    } else if item_tag == 0x87 {
        // [7] floating-point
        if item_inner.len() == 5 && item_inner[0] == 0x08 {
            let bytes = [item_inner[1], item_inner[2], item_inner[3], item_inner[4]];
            Some(format!("{}", f32::from_be_bytes(bytes)))
        } else if item_inner.len() == 9 && item_inner[0] == 0x0B {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&item_inner[1..9]);
            Some(format!("{}", f64::from_be_bytes(bytes)))
        } else {
            None
        }
    } else if item_tag == 0x89 || item_tag == 0x8A || item_tag == 0x90 {
        // [9] octet-string, [10] visible-string, [16] mms-string
        Some(parse_ber_string(item_inner))
    } else {
        // 其他类型：hex 表示
        if !item_inner.is_empty() {
            Some(item_inner.iter().map(|b| format!("{:02x}", b)).collect())
        } else {
            None
        }
    };

    MmsAccessResult {
        success: true,
        data_type: type_name,
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_data_list_mixed_values_contract() {
        let input = &[
            0x83, 0x01, 0xFF, // boolean true
            0x85, 0x01, 0xFF, // integer -1
            0x86, 0x01, 0x2A, // unsigned 42
            0x8A, 0x02, b'O', b'K', // visible-string
            0xA2, 0x06, // structure with two members
            0x83, 0x01, 0x00, 0x86, 0x01, 0x01,
        ];

        let data = parse_data_list(input, 0);
        assert_eq!(data.len(), 5);
        assert_eq!(data[0].data_type.as_deref(), Some("boolean"));
        assert_eq!(data[0].value.as_deref(), Some("true"));
        assert_eq!(data[1].data_type.as_deref(), Some("integer"));
        assert_eq!(data[1].value.as_deref(), Some("-1"));
        assert_eq!(data[2].data_type.as_deref(), Some("unsigned"));
        assert_eq!(data[2].value.as_deref(), Some("42"));
        assert_eq!(data[3].data_type.as_deref(), Some("visible-string"));
        assert_eq!(data[3].value.as_deref(), Some("OK"));
        assert_eq!(data[4].data_type.as_deref(), Some("structure"));
        assert_eq!(data[4].value.as_deref(), Some("2 items"));
    }
}
