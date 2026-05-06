//! MMS tag-to-name mapping helpers.

/// 将 TypeDescription/TypeSpecification 的 context tag 号映射为类型名称字符串。
/// 标签号对应 ISO 9506-2 ASN.1 定义，参照 libiec61850 TypeSpecification.c。
pub(super) fn type_description_tag_name(tag_num: u32) -> Option<&'static str> {
    match tag_num {
        // [0] typeName — 引用已定义的类型名称，不是具体类型描述
        1 => Some("array"),
        2 => Some("structure"),
        3 => Some("boolean"),
        4 => Some("bit-string"),
        5 => Some("integer"),
        6 => Some("unsigned"),
        7 => Some("floating-point"),
        // [8] reserved (real, 部分实现)
        9 => Some("octet-string"),
        10 => Some("visible-string"),
        11 => Some("generalized-time"),
        12 => Some("binary-time"),
        13 => Some("bcd"),
        15 => Some("obj-id"),
        16 => Some("mms-string"),
        17 => Some("utc-time"),
        _ => None,
    }
}

/// 将 Data CHOICE 的 context tag 号映射为类型名称字符串。
/// 标签号对应 ISO 9506-2 ASN.1 定义，参照 libiec61850 mms_access_result.c。
pub(super) fn data_tag_name(tag_num: u32) -> Option<&'static str> {
    match tag_num {
        1 => Some("array"),
        2 => Some("structure"),
        3 => Some("boolean"),
        4 => Some("bit-string"),
        5 => Some("integer"),
        6 => Some("unsigned"),
        7 => Some("floating-point"),
        // [8] reserved
        9 => Some("octet-string"),
        10 => Some("visible-string"),
        // [11] generalized-time (少见，暂不映射)
        12 => Some("binary-time"),
        // [13] bcd (少见，暂不映射)
        // [14] boolean-array (少见，暂不映射)
        // [15] obj-id (少见，暂不映射)
        16 => Some("mms-string"),
        17 => Some("utc-time"),
        _ => None,
    }
}

/// 将 DataAccessError 整数值映射为名称字符串。
///
/// ISO 9506-2 DataAccessError ::= INTEGER {
///   object-invalidated(0), hardware-fault(1), temporarily-unavailable(2),
///   object-access-denied(3), object-undefined(4), invalid-address(5),
///   type-unsupported(6), type-inconsistent(7), object-attribute-inconsistent(8),
///   object-access-unsupported(9), object-non-existent(10), object-value-invalid(11)
/// }
pub(super) fn data_access_error_name(val: u32) -> &'static str {
    match val {
        0 => "object-invalidated",
        1 => "hardware-fault",
        2 => "temporarily-unavailable",
        3 => "object-access-denied",
        4 => "object-undefined",
        5 => "invalid-address",
        6 => "type-unsupported",
        7 => "type-inconsistent",
        8 => "object-attribute-inconsistent",
        9 => "object-access-unsupported",
        10 => "object-non-existent",
        11 => "object-value-invalid",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_description_tag_name_contract() {
        assert_eq!(type_description_tag_name(1), Some("array"));
        assert_eq!(type_description_tag_name(2), Some("structure"));
        assert_eq!(type_description_tag_name(17), Some("utc-time"));
        assert_eq!(type_description_tag_name(0), None);
        assert_eq!(type_description_tag_name(99), None);
    }

    #[test]
    fn test_data_tag_name_contract() {
        assert_eq!(data_tag_name(1), Some("array"));
        assert_eq!(data_tag_name(3), Some("boolean"));
        assert_eq!(data_tag_name(16), Some("mms-string"));
        assert_eq!(data_tag_name(11), None);
        assert_eq!(data_tag_name(99), None);
    }

    #[test]
    fn test_data_access_error_name_contract() {
        assert_eq!(data_access_error_name(0), "object-invalidated");
        assert_eq!(data_access_error_name(10), "object-non-existent");
        assert_eq!(data_access_error_name(99), "unknown");
    }
}
