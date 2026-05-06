//! MMS Read/Write service parsing.

use super::data::{parse_data_element, parse_data_list};
use super::tags::data_access_error_name;
use super::variable_access::parse_variable_access_specification;
use crate::iec61850mms::ber::{parse_ber_integer, parse_ber_tlv, MAX_BER_DEPTH};
use crate::iec61850mms::mms_types::*;

const MAX_VARIABLE_SPECS: usize = super::MAX_VARIABLE_SPECS;

pub(super) fn parse_read_request(content: &[u8], depth: usize) -> Vec<ObjectNameRef> {
    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            if tag_byte == 0xA1 {
                return parse_variable_access_specification(inner, depth + 1);
            }
            pos = rem;
        } else {
            break;
        }
    }
    Vec::new()
}

pub(super) fn parse_write_request(content: &[u8], depth: usize) -> MmsWriteRequest {
    let mut result = MmsWriteRequest::default();

    if let Ok((_, _, _, _var_inner, rem)) = parse_ber_tlv(content) {
        result.variable_specs = parse_variable_access_specification(content, depth + 1);

        if let Ok((tag_byte, _, _, data_inner, _)) = parse_ber_tlv(rem) {
            if tag_byte == 0xA0 {
                result.data = parse_data_list(data_inner, depth + 1);
            }
        }
    }

    result
}

pub(super) fn parse_read_response(content: &[u8], depth: usize) -> MmsReadResponse {
    let mut results = Vec::new();
    if depth > MAX_BER_DEPTH {
        return MmsReadResponse { results };
    }

    if let Ok((tag_byte, _, _, inner, _)) = parse_ber_tlv(content) {
        if tag_byte == 0xA0 {
            let mut pos = inner;
            while !pos.is_empty() && results.len() < MAX_VARIABLE_SPECS {
                if let Ok((item_tag, _, item_tag_num, item_inner, item_rem)) = parse_ber_tlv(pos) {
                    if item_tag == 0x80 {
                        let val = parse_ber_integer(item_inner)
                            .map(|v| v.to_string())
                            .unwrap_or_else(|_| "malformed".to_string());
                        results.push(MmsAccessResult {
                            success: false,
                            data_type: Some("error".to_string()),
                            value: Some(val),
                        });
                    } else {
                        results.push(parse_data_element(item_tag, item_tag_num, item_inner));
                    }
                    pos = item_rem;
                } else {
                    break;
                }
            }
        }
    }

    MmsReadResponse { results }
}

pub(super) fn parse_write_response(content: &[u8], depth: usize) -> MmsWriteResponse {
    let mut results = Vec::new();
    if depth > MAX_BER_DEPTH {
        return MmsWriteResponse { results };
    }

    let mut pos = content;
    while !pos.is_empty() && results.len() < MAX_VARIABLE_SPECS {
        if let Ok((tag_byte, _, _, item_inner, item_rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0x80 => {
                    let error = parse_ber_integer(item_inner)
                        .map(data_access_error_name)
                        .unwrap_or("malformed")
                        .to_string();
                    results.push(MmsWriteResult {
                        success: false,
                        error: Some(error),
                    });
                }
                0x81 => {
                    results.push(MmsWriteResult {
                        success: true,
                        error: None,
                    });
                }
                _ => {}
            }
            pos = item_rem;
        } else {
            break;
        }
    }

    MmsWriteResponse { results }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_response_from_items(items: &[u8]) -> MmsReadResponse {
        let mut content = Vec::new();
        content.push(0xA0);
        if items.len() < 128 {
            content.push(items.len() as u8);
        } else {
            content.push(0x82);
            content.push((items.len() >> 8) as u8);
            content.push((items.len() & 0xFF) as u8);
        }
        content.extend_from_slice(items);
        parse_read_response(&content, 0)
    }

    #[test]
    fn test_parse_read_request_variable_specs_contract() {
        let input = &[
            0xA1, 0x09, // variableAccessSpecification
            0xA0, 0x07, // listOfVariable
            0x30, 0x05, 0xA0, 0x03, 0x80, 0x01, b'V',
        ];

        let specs = parse_read_request(input, 0);
        assert_eq!(specs, vec![ObjectNameRef::VmdSpecific("V".to_string())]);
    }

    #[test]
    fn test_parse_read_response_data_types_contract() {
        let items = [
            0x80, 0x01, 0x02, // failure: error=2
            0x83, 0x01, 0x01, // boolean true
            0x85, 0x01, 0xFD, // integer -3
            0x86, 0x01, 0x2A, // unsigned 42
            0x8A, 0x05, b'H', b'e', b'l', b'l', b'o',
        ];

        let resp = read_response_from_items(&items);
        assert_eq!(resp.results.len(), 5);
        assert!(!resp.results[0].success);
        assert_eq!(resp.results[0].data_type.as_deref(), Some("error"));
        assert_eq!(resp.results[0].value.as_deref(), Some("2"));
        assert_eq!(resp.results[1].data_type.as_deref(), Some("boolean"));
        assert_eq!(resp.results[1].value.as_deref(), Some("true"));
        assert_eq!(resp.results[2].data_type.as_deref(), Some("integer"));
        assert_eq!(resp.results[2].value.as_deref(), Some("-3"));
        assert_eq!(resp.results[3].data_type.as_deref(), Some("unsigned"));
        assert_eq!(resp.results[3].value.as_deref(), Some("42"));
        assert_eq!(resp.results[4].data_type.as_deref(), Some("visible-string"));
        assert_eq!(resp.results[4].value.as_deref(), Some("Hello"));
    }

    #[test]
    fn test_parse_read_response_malformed_failure_does_not_default_to_empty_contract() {
        let items = [
            0x80, 0x00, // malformed DataAccessError
        ];

        let resp = read_response_from_items(&items);
        assert_eq!(resp.results.len(), 1);
        assert!(!resp.results[0].success);
        assert_eq!(resp.results[0].data_type.as_deref(), Some("error"));
        assert_eq!(resp.results[0].value.as_deref(), Some("malformed"));
    }

    #[test]
    fn test_parse_read_response_floating_point_width_contract() {
        let float_bytes = 1.0_f32.to_be_bytes();
        let valid = [
            0x87,
            0x05,
            0x08,
            float_bytes[0],
            float_bytes[1],
            float_bytes[2],
            float_bytes[3],
        ];
        let invalid = [
            0x87,
            0x05,
            0x07,
            float_bytes[0],
            float_bytes[1],
            float_bytes[2],
            float_bytes[3],
        ];

        let valid_resp = read_response_from_items(&valid);
        assert_eq!(
            valid_resp.results[0].data_type.as_deref(),
            Some("floating-point")
        );
        assert!(valid_resp.results[0].value.as_ref().unwrap().contains("1"));

        let invalid_resp = read_response_from_items(&invalid);
        assert_eq!(
            invalid_resp.results[0].data_type.as_deref(),
            Some("floating-point")
        );
        assert!(invalid_resp.results[0].value.is_none());
    }

    #[test]
    fn test_parse_read_response_structure_and_truncation_contract() {
        let structure = [
            0xA2, 0x09, // structure
            0x83, 0x01, 0x01, 0x85, 0x01, 0x05, 0x86, 0x01, 0x0A,
        ];
        let resp = read_response_from_items(&structure);
        assert_eq!(resp.results[0].data_type.as_deref(), Some("structure"));
        assert_eq!(resp.results[0].value.as_deref(), Some("3 items"));

        let mut items = Vec::new();
        for i in 0u8..70 {
            items.extend_from_slice(&[0x86, 0x01, i]);
        }
        let truncated = read_response_from_items(&items);
        assert_eq!(truncated.results.len(), 64);
        assert_eq!(truncated.results[63].value.as_deref(), Some("63"));
    }

    #[test]
    fn test_parse_write_request_specs_and_data_contract() {
        let input = &[
            0xA0, 0x07, 0x30, 0x05, 0xA0, 0x03, 0x80, 0x01, b'V', // listOfVariable
            0xA0, 0x06, 0x85, 0x01, 0xFD, 0x86, 0x01, 0x2A, // listOfData
        ];

        let result = parse_write_request(input, 0);
        assert_eq!(
            result.variable_specs,
            vec![ObjectNameRef::VmdSpecific("V".to_string())]
        );
        assert_eq!(result.data.len(), 2);
        assert_eq!(result.data[0].data_type.as_deref(), Some("integer"));
        assert_eq!(result.data[0].value.as_deref(), Some("-3"));
        assert_eq!(result.data[1].data_type.as_deref(), Some("unsigned"));
        assert_eq!(result.data[1].value.as_deref(), Some("42"));
    }

    #[test]
    fn test_parse_write_response_success_and_failure_contract() {
        let input = &[
            0x81, 0x00, // success
            0x80, 0x01, 0x03, // object-access-denied
            0x81, 0x00, // success
        ];

        let result = parse_write_response(input, 0);
        assert_eq!(result.results.len(), 3);
        assert!(result.results[0].success);
        assert!(!result.results[1].success);
        assert_eq!(
            result.results[1].error.as_deref(),
            Some("object-access-denied")
        );
        assert!(result.results[2].success);
    }

    #[test]
    fn test_parse_write_response_malformed_failure_does_not_default_to_zero_contract() {
        let input = &[
            0x80, 0x00, // malformed DataAccessError
        ];

        let result = parse_write_response(input, 0);
        assert_eq!(result.results.len(), 1);
        assert!(!result.results[0].success);
        assert_eq!(result.results[0].error.as_deref(), Some("malformed"));
    }
}
