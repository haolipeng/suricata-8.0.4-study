//! MMS Initiate Request/Response detail parsing.

use crate::iec61850mms::ber::{parse_ber_integer, parse_ber_tlv, MAX_BER_DEPTH};
use crate::iec61850mms::mms_types::MmsInitDetail;

/// 解析 Initiate-Request/Response 内部的协商参数。
///
/// 字段布局（context-tagged），参照 libiec61850 mms_client_initiate.c:192-224：
///   [0] 0x80 localDetailCalling/Called — Integer32
///   [1] 0x81 proposedMaxServOutstandingCalling/negotiated — Integer16
///   [2] 0x82 proposedMaxServOutstandingCalled/negotiated — Integer16
///   [3] 0x83 proposedDataStructureNestingLevel/negotiated — Integer8
///   [4] 0xA4 initRequestDetail/initResponseDetail — SEQUENCE {
///         [0] versionNumber Integer16,
///         [1] parameterCBB  BIT STRING,
///         [2] servicesSupportedCalling/Called BIT STRING
///       }
pub(super) fn parse_initiate_detail(content: &[u8], depth: usize) -> MmsInitDetail {
    let mut detail = MmsInitDetail::default();
    if depth > MAX_BER_DEPTH {
        return detail;
    }
    let mut pos = content;

    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0x80 => {
                    // [0] localDetailCalling/Called — 最大 PDU 大小
                    if let Ok(v) = parse_ber_integer(inner) {
                        detail.local_detail = Some(v);
                    }
                }
                0x81 => {
                    // [1] maxServOutstandingCalling — 主叫方最大并发请求数
                    if let Ok(v) = parse_ber_integer(inner) {
                        detail.max_serv_outstanding_calling = Some(v);
                    }
                }
                0x82 => {
                    // [2] maxServOutstandingCalled — 被叫方最大并发请求数
                    if let Ok(v) = parse_ber_integer(inner) {
                        detail.max_serv_outstanding_called = Some(v);
                    }
                }
                0x83 => {
                    // [3] dataStructureNestingLevel — 数据结构嵌套层级
                    if let Ok(v) = parse_ber_integer(inner) {
                        detail.data_structure_nesting_level = Some(v);
                    }
                }
                0xA4 => {
                    // [4] initRequestDetail/initResponseDetail（CONSTRUCTED）
                    // 解析内部子字段：版本号、参数 CBB、服务支持位图
                    let mut detail_pos = inner;
                    while !detail_pos.is_empty() {
                        if let Ok((dtag, _, _, dinner, drem)) = parse_ber_tlv(detail_pos) {
                            match dtag {
                                0x80 => {
                                    // [0] versionNumber — MMS 协议版本
                                    if let Ok(v) = parse_ber_integer(dinner) {
                                        detail.version_number = Some(v);
                                    }
                                }
                                0x81 => {} // [1] parameterCBB — 暂不解析
                                0x82 => {
                                    // [2] servicesSupportedCalling/Called — 服务支持位图
                                    // BIT STRING 内容：第 1 字节为 unused bits 数，跳过
                                    if dinner.len() > 1 {
                                        detail.supported_services = Some(dinner[1..].to_vec());
                                    }
                                }
                                _ => {}
                            }
                            detail_pos = drem;
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

    detail
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiate_detail_all_top_level_fields() {
        let content = &[
            0x80, 0x01, 0x10, // localDetail
            0x81, 0x01, 0x02, // maxServOutstandingCalling
            0x82, 0x01, 0x03, // maxServOutstandingCalled
            0x83, 0x01, 0x04, // nesting level
            0xA4, 0x08, // detail
            0x80, 0x01, 0x01, // versionNumber
            0x82, 0x03, 0x00, 0xAA, 0x55, // servicesSupported
        ];

        let detail = parse_initiate_detail(content, 0);
        assert_eq!(detail.local_detail, Some(16));
        assert_eq!(detail.max_serv_outstanding_calling, Some(2));
        assert_eq!(detail.max_serv_outstanding_called, Some(3));
        assert_eq!(detail.data_structure_nesting_level, Some(4));
        assert_eq!(detail.version_number, Some(1));
        assert_eq!(detail.supported_services, Some(vec![0xAA, 0x55]));
    }

    #[test]
    fn test_initiate_detail_depth_limit_returns_default() {
        let detail = parse_initiate_detail(&[0x80, 0x01, 0x10], MAX_BER_DEPTH + 1);
        assert_eq!(detail, MmsInitDetail::default());
    }
}
