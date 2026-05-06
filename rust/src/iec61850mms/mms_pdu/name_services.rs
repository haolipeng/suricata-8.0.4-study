//! MMS name and object-attribute service parsing.

use super::object_name::parse_object_name;
use super::tags::type_description_tag_name;
use crate::iec61850mms::ber::{parse_ber_integer, parse_ber_string, parse_ber_tlv, MAX_BER_DEPTH};
use crate::iec61850mms::mms_types::*;

/// 解析GetNameList请求，提取对象类型object class,对象范围object scope, and continueAfter.
pub(super) fn parse_get_name_list_request(content: &[u8], depth: usize) -> MmsGetNameListRequest {
    let mut result = MmsGetNameListRequest::default();
    if depth > MAX_BER_DEPTH {
        return result;
    }
    let mut pos = content;

    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0xA0 => {
                    if let Ok((_, _, _, class_content, _)) = parse_ber_tlv(inner) {
                        if let Ok(class_val) = parse_ber_integer(class_content) {
                            result.object_class = Some(
                                match class_val {
                                    0 => "named_variable",
                                    1 => "scattered_access",
                                    2 => "named_variable_list",
                                    3 => "named_type",
                                    4 => "semaphore",
                                    5 => "event_condition",
                                    6 => "event_action",
                                    7 => "event_enrollment",
                                    8 => "journal",
                                    9 => "domain",
                                    10 => "program_invocation",
                                    11 => "operator_station",
                                    _ => "unknown",
                                }
                                .to_string(),
                            );
                        }
                    }
                }
                0xA1 => {
                    if let Ok((scope_tag, _, _, scope_content, _)) = parse_ber_tlv(inner) {
                        match scope_tag {
                            0x80 => {
                                result.object_scope = Some("vmd_specific".to_string());
                            }
                            0x81 => {
                                result.object_scope = Some("domain_specific".to_string());
                                result.domain_id = Some(parse_ber_string(scope_content));
                            }
                            0x82 => {
                                result.object_scope = Some("aa_specific".to_string());
                            }
                            _ => {}
                        }
                    }
                }
                0x82 => {
                    result.continue_after = Some(parse_ber_string(inner));
                }
                _ => {}
            }
            pos = rem;
        } else {
            break;
        }
    }

    result
}

pub(super) fn parse_get_var_access_attr_request(
    content: &[u8], depth: usize,
) -> MmsGetVarAccessAttrRequest {
    let mut result = MmsGetVarAccessAttrRequest { object_name: None };
    if depth > MAX_BER_DEPTH {
        return result;
    }
    if let Ok((tag_byte, _, _, inner, _)) = parse_ber_tlv(content) {
        if tag_byte == 0xA0 {
            result.object_name = parse_object_name(inner, depth + 1);
        }
    }
    result
}

pub(super) fn parse_get_named_var_list_attr_request(
    content: &[u8], depth: usize,
) -> MmsGetNamedVarListAttrRequest {
    MmsGetNamedVarListAttrRequest {
        object_name: parse_object_name(content, depth + 1),
    }
}

pub(super) fn parse_get_named_var_list_attr_response(
    content: &[u8], depth: usize,
) -> MmsGetNamedVarListAttrResponse {
    let mut mms_deletable = false;
    let mut variables = Vec::new();
    if depth > MAX_BER_DEPTH {
        return MmsGetNamedVarListAttrResponse {
            mms_deletable,
            variables,
        };
    }

    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0x80 => {
                    if !inner.is_empty() {
                        mms_deletable = inner[0] != 0x00;
                    }
                }
                0xA1 => {
                    let mut item_pos = inner;
                    while !item_pos.is_empty() {
                        if let Ok((_, _, _, item_content, item_rem)) = parse_ber_tlv(item_pos) {
                            if variables.len() < 32 {
                                if let Ok((var_tag, _, _, var_inner, _)) =
                                    parse_ber_tlv(item_content)
                                {
                                    if var_tag == 0xA0 {
                                        if let Some(name) = parse_object_name(var_inner, depth + 1)
                                        {
                                            variables.push(name);
                                        }
                                    }
                                }
                            }
                            item_pos = item_rem;
                        } else {
                            break;
                        }
                    }
                }
                _ => {}
            }
            pos = rem;
        } else {
            break;
        }
    }

    MmsGetNamedVarListAttrResponse {
        mms_deletable,
        variables,
    }
}

pub(super) fn parse_get_name_list_response(content: &[u8], depth: usize) -> MmsGetNameListResponse {
    let mut identifiers = Vec::new();
    let mut more_follows = true;
    if depth > MAX_BER_DEPTH {
        return MmsGetNameListResponse {
            identifiers,
            more_follows,
        };
    }

    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0xA0 => {
                    let mut id_pos = inner;
                    while !id_pos.is_empty() {
                        if let Ok((_, _, _, id_content, id_rem)) = parse_ber_tlv(id_pos) {
                            if identifiers.len() < 64 {
                                identifiers.push(parse_ber_string(id_content));
                            }
                            id_pos = id_rem;
                        } else {
                            break;
                        }
                    }
                }
                0x81 => {
                    if !inner.is_empty() {
                        more_follows = inner[0] != 0x00;
                    }
                }
                _ => {}
            }
            pos = rem;
        } else {
            break;
        }
    }

    MmsGetNameListResponse {
        identifiers,
        more_follows,
    }
}

pub(super) fn parse_get_var_access_attr_response(
    content: &[u8], depth: usize,
) -> MmsGetVarAccessAttrResponse {
    let mut mms_deletable = false;
    let mut type_description = None;
    if depth > MAX_BER_DEPTH {
        return MmsGetVarAccessAttrResponse {
            mms_deletable,
            type_description,
        };
    }

    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, tag_num, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0x80 => {
                    if !inner.is_empty() {
                        mms_deletable = inner[0] != 0x00;
                    }
                }
                0xA1 => {}
                _ => {
                    if type_description.is_none() {
                        if let Some(name) = type_description_tag_name(tag_num) {
                            type_description = Some(name.to_string());
                        }
                    }
                }
            }
            pos = rem;
        } else {
            break;
        }
    }

    MmsGetVarAccessAttrResponse {
        mms_deletable,
        type_description,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_name_list_request_domain_scope_contract() {
        let input = &[
            0xA0, 0x03, // objectClass
            0x80, 0x01, 0x00, // named_variable
            0xA1, 0x05, // objectScope
            0x81, 0x03, b'L', b'D', b'1', // domain_specific "LD1"
            0x82, 0x06, b'V', b'a', b'r', b'1', b'0', b'0',
        ];

        let result = parse_get_name_list_request(input, 0);
        assert_eq!(result.object_class.as_deref(), Some("named_variable"));
        assert_eq!(result.object_scope.as_deref(), Some("domain_specific"));
        assert_eq!(result.domain_id.as_deref(), Some("LD1"));
        assert_eq!(result.continue_after.as_deref(), Some("Var100"));
    }

    #[test]
    fn test_parse_get_name_list_response_truncates_at_64_contract() {
        let mut list_content = Vec::new();
        for i in 0..100u16 {
            list_content.push(0x1A);
            list_content.push(0x02);
            list_content.push((i >> 8) as u8);
            list_content.push((i & 0xFF) as u8);
        }

        let mut input = vec![0xA0, 0x82, 0x01, 0x90];
        input.extend_from_slice(&list_content);

        let result = parse_get_name_list_response(&input, 0);
        assert_eq!(result.identifiers.len(), 64);
        assert!(result.more_follows);
    }

    #[test]
    fn test_parse_get_var_access_attr_request_object_name_contract() {
        let input = &[
            0xA0, 0x0D, // name [0]
            0xA1, 0x0B, // domain-specific
            0x1A, 0x04, b'L', b'D', b'0', b'1', 0x1A, 0x03, b'M', b'o', b'd',
        ];

        let result = parse_get_var_access_attr_request(input, 0);
        assert_eq!(
            result.object_name,
            Some(ObjectNameRef::DomainSpecific {
                domain_id: "LD01".to_string(),
                item_id: "Mod".to_string(),
            })
        );
    }

    #[test]
    fn test_parse_get_var_access_attr_response_type_contract() {
        let input = &[
            0x80, 0x01, 0xFF, // mmsDeletable=true
            0xA2, 0x00, // TypeDescription [2] structure
        ];

        let result = parse_get_var_access_attr_response(input, 0);
        assert!(result.mms_deletable);
        assert_eq!(result.type_description.as_deref(), Some("structure"));
    }

    #[test]
    fn test_parse_get_named_var_list_attr_request_contract() {
        let input = &[
            0xA1, 0x0B, // domain-specific ObjectName
            0x1A, 0x04, b'D', b'O', b'M', b'1', 0x1A, 0x03, b'D', b'S', b'1',
        ];

        let result = parse_get_named_var_list_attr_request(input, 0);
        assert_eq!(
            result.object_name,
            Some(ObjectNameRef::DomainSpecific {
                domain_id: "DOM1".to_string(),
                item_id: "DS1".to_string(),
            })
        );
    }

    #[test]
    fn test_parse_get_named_var_list_attr_response_contract() {
        let input = &[
            0x80, 0x01, 0x00, // mmsDeletable=false
            0xA1, 0x1C, // listOfVariable
            0x30, 0x0C, 0xA0, 0x0A, 0xA1, 0x08, 0x1A, 0x01, b'D', 0x1A, 0x03, b'V', b'_', b'1',
            0x30, 0x0C, 0xA0, 0x0A, 0xA1, 0x08, 0x1A, 0x01, b'D', 0x1A, 0x03, b'V', b'_', b'2',
        ];

        let result = parse_get_named_var_list_attr_response(input, 0);
        assert!(!result.mms_deletable);
        assert_eq!(result.variables.len(), 2);
        assert_eq!(
            result.variables[0],
            ObjectNameRef::DomainSpecific {
                domain_id: "D".to_string(),
                item_id: "V_1".to_string(),
            }
        );
    }
}
