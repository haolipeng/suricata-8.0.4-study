/* Copyright (C) 2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! MMS PDU parser using ASN.1 BER decoding.
//!
//! MMS (Manufacturing Message Specification) uses ASN.1 BER encoding.
//! The top-level PDU is a CHOICE type with context-specific tags:
//!
//! MMS-PDU ::= CHOICE {
//!     confirmed-RequestPDU      [0] IMPLICIT Confirmed-RequestPDU,
//!     confirmed-ResponsePDU     [1] IMPLICIT Confirmed-ResponsePDU,
//!     confirmed-ErrorPDU        [2] IMPLICIT Confirmed-ErrorPDU,
//!     unconfirmed-PDU           [3] IMPLICIT Unconfirmed-PDU,
//!     rejectPDU                 [4] IMPLICIT RejectPDU,
//!     cancel-RequestPDU         [5] IMPLICIT INTEGER,
//!     cancel-ResponsePDU        [6] IMPLICIT INTEGER,
//!     cancel-ErrorPDU           [7] IMPLICIT Cancel-ErrorPDU,
//!     initiate-RequestPDU       [8] IMPLICIT Initiate-RequestPDU,
//!     initiate-ResponsePDU      [9] IMPLICIT Initiate-ResponsePDU,
//!     initiate-ErrorPDU         [10] IMPLICIT Initiate-ErrorPDU,
//!     conclude-RequestPDU       [11] IMPLICIT ConcludeRequestPDU,
//!     conclude-ResponsePDU      [12] IMPLICIT ConcludeResponsePDU,
//!     conclude-ErrorPDU         [13] IMPLICIT Conclude-ErrorPDU,
//! }

use super::ber::{parse_ber_integer, parse_ber_signed_integer, parse_ber_string, parse_ber_tlv, MAX_BER_DEPTH};
use super::mms_types::*;

/// Maximum number of variable specifications to parse from a single request.
const MAX_VARIABLE_SPECS: usize = 64;

/// Extract domain-specific object references from a Read/Write request.
/// The variable access specification in MMS uses nested constructed tags.
fn parse_variable_access_specification(content: &[u8], depth: usize) -> Vec<ObjectNameRef> {
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

/// Parse an ObjectName CHOICE, supporting all three variants.
fn parse_object_name(content: &[u8], depth: usize) -> Option<ObjectNameRef> {
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

/// 解析GetNameList请求，提取对象类型object class,对象范围object scope, and continueAfter.
///
/// GetNameListRequest ::= SEQUENCE {
///   objectClass  [0] ObjectClass,
///   objectScope  [1] CHOICE {
///     vmdSpecific      [0] IMPLICIT NULL,
///     domainSpecific   [1] IMPLICIT Identifier,
///     aaSpecific       [2] IMPLICIT NULL
///   },
///   continueAfter [2] IMPLICIT Identifier OPTIONAL
/// }
fn parse_get_name_list_request(content: &[u8], depth: usize) -> MmsGetNameListRequest {
    let mut result = MmsGetNameListRequest::default();
    if depth > MAX_BER_DEPTH {
        return result;
    }
    let mut pos = content;

    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0xA0 => {
                    // objectClass: CHOICE { ... }
                    // objectClass: 整数值映射为 MMS 对象类别名称
                    if let Ok((_, _, _, class_content, _)) = parse_ber_tlv(inner) {
                        if let Ok(class_val) = parse_ber_integer(class_content) {
                            result.object_class = Some(
                                match class_val {
                                    0 => "named_variable", //命名变量
                                    1 => "scattered_access", //分散访问
                                    2 => "named_variable_list", //命名变量列表
                                    3 => "named_type", //命名类型
                                    4 => "semaphore", //信号量
                                    5 => "event_condition", //事件条件
                                    6 => "event_action", //事件动作
                                    7 => "event_enrollment", //事件登记
                                    8 => "journal", //日志
                                    9 => "domain", //域
                                    10 => "program_invocation", //程序执行
                                    11 => "operator_station", //操作站
                                    _ => "unknown", //未知
                                }
                                .to_string(),
                            );
                        }
                    }
                }
                0xA1 => {
                    // objectScope: CHOICE
                    // [0] vmdSpecific NULL          → tag 0x80
                    // [1] domainSpecific Identifier → tag 0x81
                    // [2] aaSpecific NULL           → tag 0x82
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
                    // continueAfter: [2] IMPLICIT Identifier (VisibleString)
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
fn parse_initiate_detail(content: &[u8], depth: usize) -> MmsInitDetail {
    let mut detail = MmsInitDetail::default();
    if depth > MAX_BER_DEPTH {
        return detail;
    }
    let mut pos = content;

    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0x80 => { // [0] localDetailCalling/Called — 最大 PDU 大小
                    if let Ok(v) = parse_ber_integer(inner) {
                        detail.local_detail = Some(v);
                    }
                }
                0x81 => { // [1] maxServOutstandingCalling — 主叫方最大并发请求数
                    if let Ok(v) = parse_ber_integer(inner) {
                        detail.max_serv_outstanding_calling = Some(v);
                    }
                }
                0x82 => { // [2] maxServOutstandingCalled — 被叫方最大并发请求数
                    if let Ok(v) = parse_ber_integer(inner) {
                        detail.max_serv_outstanding_called = Some(v);
                    }
                }
                0x83 => { // [3] dataStructureNestingLevel — 数据结构嵌套层级
                    if let Ok(v) = parse_ber_integer(inner) {
                        detail.data_structure_nesting_level = Some(v);
                    }
                }
                0xA4 => { // [4] initRequestDetail/initResponseDetail（CONSTRUCTED）
                    // 解析内部子字段：版本号、参数 CBB、服务支持位图
                    let mut detail_pos = inner;
                    while !detail_pos.is_empty() {
                        if let Ok((dtag, _, _, dinner, drem)) = parse_ber_tlv(detail_pos) {
                            match dtag {
                                0x80 => { // [0] versionNumber — MMS 协议版本
                                    if let Ok(v) = parse_ber_integer(dinner) {
                                        detail.version_number = Some(v);
                                    }
                                }
                                0x81 => {} // [1] parameterCBB — 暂不解析
                                0x82 => { // [2] servicesSupportedCalling/Called — 服务支持位图
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

/// 从 BER 编码数据中解析顶层 MMS PDU。
pub(super) fn parse_mms_pdu(input: &[u8]) -> Result<MmsPdu, ()> {
    // 如果输入数据为空，则返回错误
    if input.is_empty() {
        return Err(());
    }

    // 解析 BER 编码的 MMS PDU，获取tag_num
    let (tag_byte, _is_constructed, tag_num, content, _remaining) = parse_ber_tlv(input)?;
    let _class = (tag_byte >> 6) & 0x03;

    // MMS PDU is a CHOICE with context-specific tags
    match tag_num {
        0 => {
            //解析ConfirmedRequest确认请求
            parse_confirmed_request(content, 1)
        }
        1 => {
            //解析ConfirmedResponse确认响应
            parse_confirmed_response(content, 1)
        }
        2 => {
            //解析ConfirmedError确认错误
            parse_confirmed_error(content, 1)
        }
        3 => {
            //解析UnconfirmedPdu未确认 PDU
            parse_unconfirmed_pdu(content, 1)
        }
        4 => {
            //解析RejectPdu拒绝 PDU
            // RejectPDU 中 originalInvokeID 是 OPTIONAL [0] IMPLICIT Unsigned32。
            // 需区分"字段不存在"（合法 → None）和"字段存在但畸形"（→ Err）。
            let invoke_id = if content.is_empty() {
                None
            } else {
                let (tag_byte, _, _, inner, _) = parse_ber_tlv(content)?;
                if tag_byte == 0x80 {
                    // invoke_id 字段存在，必须能解析为整数
                    Some(parse_ber_integer(inner)?)
                } else {
                    // 第一个字段不是 invoke_id（是 rejectReason），合法的 None
                    None
                }
            };
            Ok(MmsPdu::RejectPdu { invoke_id })
        }
        5 => {
            //解析CancelRequest取消请求
            // CancelRequestPDU ::= INTEGER（invoke_id 是 PDU 的全部内容）
            let invoke_id = parse_ber_integer(content)?;
            Ok(MmsPdu::CancelRequest { invoke_id })
        }
        6 => {
            //解析CancelResponse取消响应
            let invoke_id = parse_ber_integer(content)?;
            Ok(MmsPdu::CancelResponse { invoke_id })
        }
        7 => Ok(MmsPdu::CancelError),
        8 => {
            //解析InitiateRequest初始化请求
            let detail = parse_initiate_detail(content, 1);
            Ok(MmsPdu::InitiateRequest { detail: Some(detail) })
        }
        9 => {
            //解析InitiateResponse初始化响应
            let detail = parse_initiate_detail(content, 1);
            Ok(MmsPdu::InitiateResponse { detail: Some(detail) })
        }
        10 => Ok(MmsPdu::InitiateError),
        11 => Ok(MmsPdu::ConcludeRequest),
        12 => Ok(MmsPdu::ConcludeResponse),
        13 => Ok(MmsPdu::ConcludeError),
        _ => Err(()),
    }
}

/// Parse the first INTEGER in a constructed type.
fn parse_first_integer(content: &[u8]) -> Result<u32, ()> {
    let (tag_byte, _, _, int_content, _) = parse_ber_tlv(content)?;
    // Universal INTEGER tag = 0x02
    if tag_byte == 0x02 {
        parse_ber_integer(int_content)
    } else {
        // Could be context-tagged [0] for invoke-id
        if tag_byte == 0x80 {
            parse_ber_integer(int_content)
        } else {
            Err(())
        }
    }
}

/// Parse a Confirmed-RequestPDU.
///
/// Confirmed-RequestPDU ::= SEQUENCE {
///   invokeID  Unsigned32,
///   confirmedServiceRequest  ConfirmedServiceRequest
/// }
fn parse_confirmed_request(content: &[u8], depth: usize) -> Result<MmsPdu, ()> {
    if depth > MAX_BER_DEPTH {
        return Err(());
    }
    // 第一个元素：invokeID（INTEGER），用于请求/响应配对
    let (_, _, _, id_content, rest) = parse_ber_tlv(content)?;
    let invoke_id = parse_ber_integer(id_content)?;

    // 第二个元素：confirmedServiceRequest（CHOICE），按上下文标签分发到具体服务
    let (service_tag, _, service_num, service_content, _) = parse_ber_tlv(rest)?;
    let _ = service_tag;
    let service = MmsConfirmedService::from_request_tag(service_num);

    let mut read_info = None;
    let mut write_info = None;
    let mut get_name_list_info = None;
    let mut get_var_access_attr_info = None;
    let mut get_named_var_list_attr_info = None;
    let mut file_open_info = None;
    let mut file_read_info = None;

    match service {
        MmsConfirmedService::Read => {
            let specs = parse_read_request(service_content, depth + 1);
            if !specs.is_empty() {
                read_info = Some(MmsReadRequest {
                    variable_specs: specs,
                });
            }
        }
        MmsConfirmedService::Write => {
            let wi = parse_write_request(service_content, depth + 1);
            if !wi.variable_specs.is_empty() || !wi.data.is_empty() {
                write_info = Some(wi);
            }
        }
        MmsConfirmedService::GetNameList => {
            get_name_list_info = Some(parse_get_name_list_request(service_content, depth + 1));
        }
        MmsConfirmedService::GetVariableAccessAttributes => {
            get_var_access_attr_info = Some(parse_get_var_access_attr_request(service_content, depth + 1));
        }
        MmsConfirmedService::GetNamedVariableListAttributes => {
            get_named_var_list_attr_info = Some(parse_get_named_var_list_attr_request(service_content, depth + 1));
        }
        MmsConfirmedService::FileOpen => {
            file_open_info = parse_file_open_request(service_content, depth + 1);
        }
        MmsConfirmedService::FileRead | MmsConfirmedService::FileClose => {
            // FileRead-Request / FileClose-Request ::= Integer32 (frsmID)
            if let Ok(frsm_id) = parse_ber_integer(service_content) {
                file_read_info = Some(MmsFileReadRequest { frsm_id });
            }
        }
        _ => {}
    }

    Ok(MmsPdu::ConfirmedRequest {
        invoke_id,
        service,
        read_info,
        write_info,
        get_name_list_info,
        get_var_access_attr_info,
        get_named_var_list_attr_info,
        file_open_info,
        file_read_info,
    })
}

/// Parse Read request body to extract variable specifications.
fn parse_read_request(content: &[u8], depth: usize) -> Vec<ObjectNameRef> {
    // ReadRequest ::= SEQUENCE {
    //   specificationWithResult [0] IMPLICIT BOOLEAN DEFAULT FALSE,
    //   variableAccessSpecification [1] VariableAccessSpecification
    // }
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

/// Parse Write request body to extract variable specifications and data values.
fn parse_write_request(content: &[u8], depth: usize) -> MmsWriteRequest {
    // WriteRequest ::= SEQUENCE {
    //   variableAccessSpecification VariableAccessSpecification,
    //   listOfData [0] IMPLICIT SEQUENCE OF Data
    // }
    // 两个字段都使用 [0] tag：variableAccessSpecification 的 listOfVariable [0]
    // 和 listOfData [0]。靠位置顺序区分：第一个是变量列表，第二个是数据列表。
    let mut result = MmsWriteRequest::default();

    if let Ok((_, _, _, _var_inner, rem)) = parse_ber_tlv(content) {
        // 第一个 TLV：variableAccessSpecification
        // var_inner 已经是 listOfVariable [0] 的内容，
        // 但 parse_variable_access_specification 需要看到完整的 [0] tag，
        // 所以传入原始 content 让它自己解析。
        result.variable_specs = parse_variable_access_specification(content, depth + 1);

        // 第二个 TLV：listOfData [0]
        if let Ok((tag_byte, _, _, data_inner, _)) = parse_ber_tlv(rem) {
            if tag_byte == 0xA0 {
                result.data = parse_data_list(data_inner, depth + 1);
            }
        }
    }

    result
}

/// Parse a list of MMS Data elements with shallow interpretation.
/// Used by both Write request (listOfData) and Read response (listOfAccessResult success items).
fn parse_data_list(content: &[u8], depth: usize) -> Vec<MmsAccessResult> {
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
fn parse_data_element(item_tag: u8, item_tag_num: u32, item_inner: &[u8]) -> MmsAccessResult {
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
        parse_ber_signed_integer(item_inner).map(|v| v.to_string()).ok()
    } else if item_tag == 0x86 {
        // [6] unsigned
        parse_ber_integer(item_inner).map(|v| v.to_string()).ok()
    } else if item_tag == 0x87 {
        // [7] floating-point
        if item_inner.len() == 5 {
            let bytes = [item_inner[1], item_inner[2], item_inner[3], item_inner[4]];
            Some(format!("{}", f32::from_be_bytes(bytes)))
        } else if item_inner.len() == 9 {
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

/// Parse GetVariableAccessAttributes request.
fn parse_get_var_access_attr_request(content: &[u8], depth: usize) -> MmsGetVarAccessAttrRequest {
    let mut result = MmsGetVarAccessAttrRequest { object_name: None };
    if depth > MAX_BER_DEPTH {
        return result;
    }
    if let Ok((tag_byte, _, _, inner, _)) = parse_ber_tlv(content) {
        match tag_byte {
            0xA0 => {
                result.object_name = parse_object_name(inner, depth + 1);
            }
            _ => {}
        }
    }
    result
}

/// Parse GetNamedVariableListAttributes request.
///
/// GetNamedVariableListAttributes-Request ::= ObjectName
///   ObjectName ::= CHOICE {
///     vmd-specific     [0] IMPLICIT Identifier,
///     domain-specific  [1] IMPLICIT SEQUENCE { domainId, itemId },
///     aa-specific      [2] IMPLICIT Identifier
///   }
fn parse_get_named_var_list_attr_request(content: &[u8], depth: usize) -> MmsGetNamedVarListAttrRequest {
    MmsGetNamedVarListAttrRequest {
        object_name: parse_object_name(content, depth + 1),
    }
}

/// 解析 FileOpen-Request。
///
/// FileOpen-Request ::= SEQUENCE {
///     fileName         [0] IMPLICIT SEQUENCE OF GraphicString,
///     initialPosition  [1] IMPLICIT Unsigned32
/// }
///
/// fileName 是一个路径段列表，多段时用 "/" 拼接。
fn parse_file_open_request(content: &[u8], depth: usize) -> Option<MmsFileOpenRequest> {
    if depth > MAX_BER_DEPTH || content.is_empty() {
        return None;
    }

    // 第一个 TLV: fileName [0] IMPLICIT SEQUENCE OF GraphicString
    let (tag_byte, _, _, inner, rem) = parse_ber_tlv(content).ok()?;
    if tag_byte != 0xA0 {
        return None;
    }

    // 解析 SEQUENCE OF GraphicString — 逐个提取路径段
    let mut segments = Vec::new();
    let mut pos = inner;
    while !pos.is_empty() && segments.len() < 16 {
        if let Ok((_, _, _, seg_content, seg_rem)) = parse_ber_tlv(pos) {
            let seg = parse_ber_string(seg_content);
            if !seg.is_empty() {
                segments.push(seg);
            }
            pos = seg_rem;
        } else {
            break;
        }
    }

    let file_name = if segments.len() == 1 {
        segments.into_iter().next().unwrap()
    } else {
        segments.join("/")
    };

    // 第二个 TLV: initialPosition [1] IMPLICIT Unsigned32
    let mut initial_position = 0u32;
    if !rem.is_empty() {
        if let Ok((tag2, _, _, pos_content, _)) = parse_ber_tlv(rem) {
            if tag2 == 0x81 {
                initial_position = parse_ber_integer(pos_content).unwrap_or(0);
            }
        }
    }

    Some(MmsFileOpenRequest {
        file_name,
        initial_position,
    })
}

/// 解析 GetNamedVariableListAttributes 响应.
///
/// GetNamedVariableListAttributes-Response ::= SEQUENCE {
///   mmsDeletable    [0] IMPLICIT BOOLEAN,
///   listOfVariable  [1] IMPLICIT SEQUENCE OF SEQUENCE {
///     variableSpecification  VariableSpecification
///   }
/// }
fn parse_get_named_var_list_attr_response(content: &[u8], depth: usize) -> MmsGetNamedVarListAttrResponse {
    let mut mms_deletable = false;
    let mut variables = Vec::new();
    if depth > MAX_BER_DEPTH {
        return MmsGetNamedVarListAttrResponse { mms_deletable, variables };
    }

    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0x80 => {
                    // [0] mmsDeletable: BOOLEAN
                    if !inner.is_empty() {
                        mms_deletable = inner[0] != 0x00;
                    }
                }
                0xA1 => {
                    // [1] listOfVariable: SEQUENCE OF SEQUENCE { variableSpecification, ... }
                    let mut item_pos = inner;
                    while !item_pos.is_empty() {
                        if let Ok((_, _, _, item_content, item_rem)) = parse_ber_tlv(item_pos) {
                            if variables.len() < 32 {
                                // 每个 item 是 SEQUENCE { variableSpecification VariableSpecification, ... }
                                // variableSpecification: name [0] ObjectName
                                if let Ok((var_tag, _, _, var_inner, _)) = parse_ber_tlv(item_content) {
                                    if var_tag == 0xA0 {
                                        if let Some(name) = parse_object_name(var_inner, depth + 1) {
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

/// Parse a GetNameList response.
///
/// GetNameListResponse ::= SEQUENCE {
///   listOfIdentifier [0] IMPLICIT SEQUENCE OF Identifier,
///   moreFollows      [1] IMPLICIT BOOLEAN DEFAULT TRUE
/// }
fn parse_get_name_list_response(content: &[u8], depth: usize) -> MmsGetNameListResponse {
    let mut identifiers = Vec::new();
    let mut more_follows = true; // ASN.1 DEFAULT TRUE
    if depth > MAX_BER_DEPTH {
        return MmsGetNameListResponse { identifiers, more_follows };
    }

    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0xA0 => {
                    // [0] listOfIdentifier: SEQUENCE OF Identifier (VisibleString)
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
                    // [1] moreFollows: BOOLEAN
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

/// 将 TypeDescription/TypeSpecification 的 context tag 号映射为类型名称字符串。
/// 标签号对应 ISO 9506-2 ASN.1 定义，参照 libiec61850 TypeSpecification.c。
fn type_description_tag_name(tag_num: u32) -> Option<&'static str> {
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
fn data_tag_name(tag_num: u32) -> Option<&'static str> {
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

/// 解析 GetVariableAccessAttributes-Response。
///
/// GetVariableAccessAttributes-Response ::= SEQUENCE {
///     mmsDeletable     [0] IMPLICIT BOOLEAN,
///     address          [1] IMPLICIT Address OPTIONAL,
///     typeDescription  TypeDescription (context-tagged CHOICE)
/// }
fn parse_get_var_access_attr_response(content: &[u8], depth: usize) -> MmsGetVarAccessAttrResponse {
    let mut mms_deletable = false;
    let mut type_description = None;
    if depth > MAX_BER_DEPTH {
        return MmsGetVarAccessAttrResponse { mms_deletable, type_description };
    }

    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, tag_num, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0x80 => {
                    // [0] mmsDeletable: BOOLEAN
                    if !inner.is_empty() {
                        mms_deletable = inner[0] != 0x00;
                    }
                }
                0xA1 => {
                    // [1] address: 跳过
                }
                _ => {
                    // typeDescription: context-tagged CHOICE
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

/// 解析 Read-Response。
///
/// Read-Response ::= SEQUENCE {
///     listOfAccessResult [0] IMPLICIT SEQUENCE OF AccessResult
/// }
///
/// AccessResult ::= CHOICE {
///     failure [0] IMPLICIT DataAccessError (INTEGER),
///     Data    [1]-[14] ...
/// }
fn parse_read_response(content: &[u8], depth: usize) -> MmsReadResponse {
    let mut results = Vec::new();
    if depth > MAX_BER_DEPTH {
        return MmsReadResponse { results };
    }

    // 外层 [0] listOfAccessResult
    if let Ok((tag_byte, _, _, inner, _)) = parse_ber_tlv(content) {
        if tag_byte == 0xA0 {
            let mut pos = inner;
            while !pos.is_empty() && results.len() < MAX_VARIABLE_SPECS {
                if let Ok((item_tag, _, item_tag_num, item_inner, item_rem)) = parse_ber_tlv(pos) {
                    if item_tag == 0x80 {
                        // failure: DataAccessError INTEGER
                        let val = parse_ber_integer(item_inner)
                            .map(|v| v.to_string())
                            .unwrap_or_default();
                        results.push(MmsAccessResult {
                            success: false,
                            data_type: Some("error".to_string()),
                            value: Some(val),
                        });
                    } else {
                        // success Data
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

/// 将 DataAccessError 整数值映射为名称字符串。
///
/// ISO 9506-2 DataAccessError ::= INTEGER {
///   object-invalidated(0), hardware-fault(1), temporarily-unavailable(2),
///   object-access-denied(3), object-undefined(4), invalid-address(5),
///   type-unsupported(6), type-inconsistent(7), object-attribute-inconsistent(8),
///   object-access-unsupported(9), object-non-existent(10), object-value-invalid(11)
/// }
fn data_access_error_name(val: u32) -> &'static str {
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

/// 解析 Write-Response。
///
/// Write-Response ::= SEQUENCE OF CHOICE {
///     failure [0] IMPLICIT DataAccessError (INTEGER),
///     success [1] IMPLICIT NULL
/// }
fn parse_write_response(content: &[u8], depth: usize) -> MmsWriteResponse {
    let mut results = Vec::new();
    if depth > MAX_BER_DEPTH {
        return MmsWriteResponse { results };
    }

    let mut pos = content;
    while !pos.is_empty() && results.len() < MAX_VARIABLE_SPECS {
        if let Ok((tag_byte, _, _, item_inner, item_rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0x80 => {
                    // failure [0] IMPLICIT DataAccessError (INTEGER)
                    let error_val = parse_ber_integer(item_inner).unwrap_or(0);
                    results.push(MmsWriteResult {
                        success: false,
                        error: Some(data_access_error_name(error_val).to_string()),
                    });
                }
                0x81 => {
                    // success [1] IMPLICIT NULL
                    results.push(MmsWriteResult {
                        success: true,
                        error: None,
                    });
                }
                _ => {
                    // 未知标签，跳过
                }
            }
            pos = item_rem;
        } else {
            break;
        }
    }

    MmsWriteResponse { results }
}

/// 解析 FileOpen-Response。
///
/// FileOpen-Response ::= SEQUENCE {
///     frsmID         [0] IMPLICIT Integer32,
///     fileAttributes [1] IMPLICIT FileAttributes
/// }
/// FileAttributes ::= SEQUENCE {
///     sizeOfFile    [0] IMPLICIT Unsigned32,
///     lastModified  [1] IMPLICIT GeneralizedTime OPTIONAL
/// }
fn parse_file_open_response(content: &[u8], depth: usize) -> Option<MmsFileOpenResponse> {
    if depth > MAX_BER_DEPTH || content.is_empty() {
        return None;
    }

    // frsmID [0] IMPLICIT Integer32
    let (tag_byte, _, _, inner, rem) = parse_ber_tlv(content).ok()?;
    if tag_byte != 0x80 {
        return None;
    }
    let frsm_id = parse_ber_integer(inner).unwrap_or(0);

    let mut file_size = None;
    let mut last_modified = None;

    // fileAttributes [1] IMPLICIT FileAttributes (SEQUENCE)
    if !rem.is_empty() {
        if let Ok((tag2, _, _, attr_inner, _)) = parse_ber_tlv(rem) {
            if tag2 == 0xA1 {
                let mut pos = attr_inner;
                while !pos.is_empty() {
                    if let Ok((attr_tag, _, _, attr_content, attr_rem)) = parse_ber_tlv(pos) {
                        match attr_tag {
                            0x80 => {
                                // sizeOfFile [0] IMPLICIT Unsigned32
                                file_size = parse_ber_integer(attr_content).ok();
                            }
                            0x81 => {
                                // lastModified [1] IMPLICIT GeneralizedTime
                                last_modified = Some(parse_ber_string(attr_content));
                            }
                            _ => {}
                        }
                        pos = attr_rem;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    Some(MmsFileOpenResponse {
        frsm_id,
        file_size,
        last_modified,
    })
}

/// 解析 FileRead-Response。
///
/// FileRead-Response ::= SEQUENCE {
///     fileData     [0] IMPLICIT OCTET STRING,
///     moreFollows  [1] IMPLICIT BOOLEAN DEFAULT TRUE
/// }
fn parse_file_read_response(content: &[u8], depth: usize) -> Option<MmsFileReadResponse> {
    if depth > MAX_BER_DEPTH || content.is_empty() {
        return None;
    }

    // fileData [0] IMPLICIT OCTET STRING — 只取长度
    let (tag_byte, _, _, inner, rem) = parse_ber_tlv(content).ok()?;
    if tag_byte != 0x80 {
        return None;
    }
    let data_length = inner.len() as u32;

    // moreFollows [1] IMPLICIT BOOLEAN DEFAULT TRUE
    let mut more_follows = true; // ASN.1 DEFAULT TRUE
    if !rem.is_empty() {
        if let Ok((tag2, _, _, bool_content, _)) = parse_ber_tlv(rem) {
            if tag2 == 0x81 && !bool_content.is_empty() {
                more_follows = bool_content[0] != 0;
            }
        }
    }

    Some(MmsFileReadResponse {
        data_length,
        more_follows,
    })
}

/// Parse a Confirmed-ResponsePDU.
fn parse_confirmed_response(content: &[u8], depth: usize) -> Result<MmsPdu, ()> {
    if depth > MAX_BER_DEPTH {
        return Err(());
    }
    // invokeID
    let (_, _, _, id_content, rest) = parse_ber_tlv(content)?;
    let invoke_id = parse_ber_integer(id_content)?;

    // confirmedServiceResponse - may be absent in minimal responses
    if rest.is_empty() {
        return Ok(MmsPdu::ConfirmedResponse {
            invoke_id,
            service: MmsConfirmedService::Unknown(0),
            get_name_list_info: None,
            get_named_var_list_attr_info: None,
            read_info: None,
            get_var_access_attr_info: None,
            write_info: None,
            file_open_info: None,
            file_read_info: None,
        });
    }

    let (_, _, service_num, service_content, _) = parse_ber_tlv(rest)?;
    let service = MmsConfirmedService::from_response_tag(service_num);

    let mut get_name_list_info = None;
    let mut get_named_var_list_attr_info = None;
    let mut read_info = None;
    let mut get_var_access_attr_info = None;
    let mut write_info = None;
    let mut file_open_info = None;
    let mut file_read_info = None;
    if service == MmsConfirmedService::GetNameList {
        get_name_list_info = Some(parse_get_name_list_response(service_content, depth + 1));
    } else if service == MmsConfirmedService::GetNamedVariableListAttributes {
        get_named_var_list_attr_info = Some(parse_get_named_var_list_attr_response(service_content, depth + 1));
    } else if service == MmsConfirmedService::Read {
        read_info = Some(parse_read_response(service_content, depth + 1));
    } else if service == MmsConfirmedService::GetVariableAccessAttributes {
        get_var_access_attr_info = Some(parse_get_var_access_attr_response(service_content, depth + 1));
    } else if service == MmsConfirmedService::Write {
        write_info = Some(parse_write_response(service_content, depth + 1));
    } else if service == MmsConfirmedService::FileOpen {
        file_open_info = parse_file_open_response(service_content, depth + 1);
    } else if service == MmsConfirmedService::FileRead {
        file_read_info = parse_file_read_response(service_content, depth + 1);
    }

    Ok(MmsPdu::ConfirmedResponse {
        invoke_id,
        service,
        get_name_list_info,
        get_named_var_list_attr_info,
        read_info,
        get_var_access_attr_info,
        write_info,
        file_open_info,
        file_read_info,
    })
}

/// 将 ServiceError.errorClass 的 context tag 号映射为错误类别名称。
fn error_class_tag_name(tag_num: u32) -> Option<&'static str> {
    match tag_num {
        0 => Some("vmd-state"),
        1 => Some("application-reference"),
        2 => Some("definition"),
        3 => Some("resource"),
        4 => Some("service"),
        5 => Some("service-preempt"),
        6 => Some("time-resolution"),
        7 => Some("access"),
        8 => Some("initiate"),
        9 => Some("conclude"),
        10 => Some("cancel"),
        11 => Some("file"),
        12 => Some("others"),
        _ => None,
    }
}

/// 将错误码映射为名称字符串，根据所属的 errorClass 不同含义不同。
fn error_code_name(error_class_tag: u32, code: u32) -> Option<&'static str> {
    match error_class_tag {
        // vmd-state
        0 => match code {
            0 => Some("other"),
            1 => Some("vmd-state-conflict"),
            2 => Some("vmd-operational-problem"),
            3 => Some("domain-transfer-problem"),
            4 => Some("state-machine-id-invalid"),
            _ => None,
        },
        // application-reference
        1 => match code {
            0 => Some("other"),
            1 => Some("aplication-unreachable"),
            2 => Some("connection-lost"),
            3 => Some("application-reference-invalid"),
            4 => Some("context-unsupported"),
            _ => None,
        },
        // definition
        2 => match code {
            0 => Some("other"),
            1 => Some("object-undefined"),
            2 => Some("invalid-address"),
            3 => Some("type-unsupported"),
            4 => Some("type-inconsistent"),
            5 => Some("object-exists"),
            6 => Some("object-attribute-inconsistent"),
            _ => None,
        },
        // resource
        3 => match code {
            0 => Some("other"),
            1 => Some("memory-unavailable"),
            2 => Some("processor-resource-unavailable"),
            3 => Some("mass-storage-unavailable"),
            4 => Some("capability-unavailable"),
            5 => Some("capability-unknown"),
            _ => None,
        },
        // service
        4 => match code {
            0 => Some("other"),
            1 => Some("primitives-out-of-sequence"),
            2 => Some("object-state-conflict"),
            3 => Some("pdu-size"),
            4 => Some("continuation-invalid"),
            5 => Some("object-constraint-conflict"),
            _ => None,
        },
        // service-preempt
        5 => match code {
            0 => Some("other"),
            1 => Some("timeout"),
            2 => Some("deadlock"),
            3 => Some("cancel"),
            _ => None,
        },
        // time-resolution
        6 => match code {
            0 => Some("other"),
            1 => Some("unsupportable-time-resolution"),
            _ => None,
        },
        // access (ServiceError.errorClass.access — 与 DataAccessError 不同!)
        7 => match code {
            0 => Some("other"),
            1 => Some("object-access-unsupported"),
            2 => Some("object-non-existent"),
            3 => Some("object-access-denied"),
            4 => Some("object-invalidated"),
            _ => None,
        },
        // initiate
        8 => match code {
            0 => Some("other"),
            1 => Some("version-incompatible"),
            2 => Some("max-segment-insufficient"),
            3 => Some("max-services-outstanding-calling-insufficient"),
            4 => Some("max-services-outstanding-called-insufficient"),
            5 => Some("service-CBB-insufficient"),
            6 => Some("parameter-CBB-insufficient"),
            7 => Some("nesting-level-insufficient"),
            _ => None,
        },
        // conclude
        9 => match code {
            0 => Some("other"),
            1 => Some("further-communication-required"),
            _ => None,
        },
        // cancel
        10 => match code {
            0 => Some("other"),
            1 => Some("invoke-id-unknown"),
            2 => Some("cancel-not-possible"),
            _ => None,
        },
        // file
        11 => match code {
            0 => Some("other"),
            1 => Some("filename-ambiguous"),
            2 => Some("file-busy"),
            3 => Some("filename-syntax-error"),
            4 => Some("content-type-invalid"),
            5 => Some("position-invalid"),
            6 => Some("file-access-denied"),
            7 => Some("file-non-existent"),
            8 => Some("duplicate-filename"),
            9 => Some("insufficient-space-in-filestore"),
            _ => None,
        },
        // others
        12 => match code {
            0 => Some("other"),
            _ => None,
        },
        _ => None,
    }
}

/// 解析 Confirmed-ErrorPDU。
/// Confirmed-ErrorPDU ::= SEQUENCE {
///     invokeID         [0] IMPLICIT Unsigned32,
///     modifierPosition [1] IMPLICIT Unsigned32 OPTIONAL,
///     serviceError     [2] IMPLICIT ServiceError
/// }
/// ServiceError ::= SEQUENCE {
///     errorClass [0] CHOICE { vmd-state [0], ..., others [12] }
///     ...
/// }
fn parse_confirmed_error(content: &[u8], depth: usize) -> Result<MmsPdu, ()> {
    if depth > MAX_BER_DEPTH {
        return Err(());
    }

    let mut invoke_id = 0u32;
    let mut error_class: Option<String> = None;
    let mut error_code: Option<String> = None;
    let mut pos = content;

    while !pos.is_empty() {
        let (tag_byte, _, tag_num, inner, rem) = parse_ber_tlv(pos)?;
        match tag_byte {
            0x02 | 0x80 => {
                // invokeID: Universal INTEGER (0x02) 或 context [0] (0x80)
                invoke_id = parse_ber_integer(inner)?;
            }
            0x81 => {
                // modifierPosition [1]：跳过
            }
            0xA2 => {
                // serviceError [2] CONSTRUCTED — 解析内部 errorClass
                if let Ok((_, _, _, error_class_content, _)) = parse_ber_tlv(inner) {
                    // errorClass [0] CONSTRUCTED 内部是 CHOICE，
                    // 每个选项是 context-tagged INTEGER
                    if let Ok((_, _, ec_tag_num, ec_inner, _)) = parse_ber_tlv(error_class_content) {
                        error_class = error_class_tag_name(ec_tag_num).map(|s| s.to_string());
                        if let Ok(code) = parse_ber_integer(ec_inner) {
                            error_code = error_code_name(ec_tag_num, code)
                                .map(|s| s.to_string())
                                .or_else(|| Some(code.to_string()));
                        }
                    }
                }
            }
            _ => {
                // 未知标签，如果是 context [0] constructed 也可能是 invokeID
                if tag_num == 0 && tag_byte == 0xA0 {
                    // 某些编码将 errorClass [0] 放在顶层
                }
            }
        }
        pos = rem;
    }

    Ok(MmsPdu::ConfirmedError {
        invoke_id,
        error_class,
        error_code,
    })
}

/// Parse an Unconfirmed-PDU.
fn parse_unconfirmed_pdu(content: &[u8], depth: usize) -> Result<MmsPdu, ()> {
    if depth > MAX_BER_DEPTH {
        return Err(());
    }
    // UnconfirmedPDU ::= SEQUENCE {
    //   unconfirmedService UnconfirmedService
    // }
    let (_, _, tag_num, _, _) = parse_ber_tlv(content)?;
    let service = MmsUnconfirmedService::from_tag(tag_num);
    Ok(MmsPdu::UnconfirmedPdu { service })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_initiate_request() {
        // MMS Initiate-Request: tag=0xA8 (context [8] constructed)
        // content is a SEQUENCE with various parameters
        let _pdu = [
            0xA8, 0x04, // [8] CONSTRUCTED, length=4
            0x80, 0x01, 0x01, // [0] localDetailCalling = 1
            0x81, // incomplete, but we just detect the PDU type
        ];
        // The parse will work with the first 6 bytes
        let data = &[0xA8, 0x03, 0x80, 0x01, 0x01];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        match result.unwrap() {
            MmsPdu::InitiateRequest { detail } => {
                let d = detail.unwrap();
                assert_eq!(d.local_detail, Some(1));
            }
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_initiate_response() {
        let data = &[0xA9, 0x03, 0x80, 0x01, 0x01];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        match result.unwrap() {
            MmsPdu::InitiateResponse { detail } => {
                let d = detail.unwrap();
                assert_eq!(d.local_detail, Some(1));
            }
            other => panic!("Expected InitiateResponse, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_conclude_request() {
        // ConcludeRequest: [11] (0xAB) with empty content
        let data = &[0xAB, 0x00];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MmsPdu::ConcludeRequest);
    }

    #[test]
    fn test_parse_conclude_response() {
        let data = &[0xAC, 0x00];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MmsPdu::ConcludeResponse);
    }

    #[test]
    fn test_parse_confirmed_request_read() {
        // Confirmed-Request: [0] CONSTRUCTED
        //   invokeID: INTEGER 1
        //   service: Read [4]
        let data = &[
            0xA0, 0x1A, // [0] CONSTRUCTED, length=26
            0x02, 0x01, 0x01, // INTEGER invokeID = 1
            0xA4, 0x15, // [4] Read CONSTRUCTED, length=21
            0xA1, 0x13, // [1] variableAccessSpec
            0xA0, 0x11, // [0] listOfVariable
            0x30, 0x0F, // SEQUENCE
            0xA0, 0x0D, // [0] name
            0xA1, 0x0B, // [1] domain-specific
            0x1A, 0x04, 0x4C, 0x4C, 0x4E, 0x30, // VisibleString "LLN0"
            0x1A, 0x03, 0x4D, 0x6F, 0x64, // VisibleString "Mod"
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        let pdu = result.unwrap();
        match &pdu {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                service,
                read_info,
                ..
            } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::Read);
                assert!(read_info.is_some());
                let ri = read_info.as_ref().unwrap();
                assert_eq!(ri.variable_specs.len(), 1);
                assert_eq!(
                    ri.variable_specs[0],
                    ObjectNameRef::DomainSpecific {
                        domain_id: "LLN0".to_string(),
                        item_id: "Mod".to_string(),
                    }
                );
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_confirmed_response_read() {
        // Confirmed-Response: [1] CONSTRUCTED
        //   invokeID: INTEGER 1
        //   service: Read [4]
        let data = &[
            0xA1, 0x08, // [1] CONSTRUCTED, length=8
            0x02, 0x01, 0x01, // INTEGER invokeID = 1
            0xA4, 0x03, // [4] Read CONSTRUCTED
            0xA1, 0x01, 0x00, // some response data
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        match result.unwrap() {
            MmsPdu::ConfirmedResponse { invoke_id, service, .. } => {
                assert_eq!(invoke_id, 1);
                assert_eq!(service, MmsConfirmedService::Read);
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    #[test]
    fn test_parse_unconfirmed_information_report() {
        // Unconfirmed [3] containing InformationReport [0]
        let data = &[
            0xA3, 0x04, // [3] CONSTRUCTED
            0xA0, 0x02, // [0] InformationReport
            0x30, 0x00, // empty SEQUENCE
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        match result.unwrap() {
            MmsPdu::UnconfirmedPdu { service } => {
                assert_eq!(service, MmsUnconfirmedService::InformationReport);
            }
            _ => panic!("Expected UnconfirmedPdu"),
        }
    }

    #[test]
    fn test_parse_reject() {
        // Reject [4] with invokeID
        let data = &[
            0xA4, 0x06, // [4] CONSTRUCTED
            0x80, 0x01, 0x05, // [0] invokeID = 5
            0xA1, 0x01, 0x02, // reason
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        match result.unwrap() {
            MmsPdu::RejectPdu { invoke_id } => {
                assert_eq!(invoke_id, Some(5));
            }
            _ => panic!("Expected RejectPdu"),
        }
    }

    // ====== GetNameList Request/Response 深度解析测试 ======

    #[test]
    fn test_get_name_list_request_vmd_specific() {
        // GetNameList Request: objectClass=domain(9), objectScope=vmdSpecific
        // basicObjectClass [0] IMPLICIT INTEGER → tag 0x80 (primitive)
        let data = &[
            0xA0, 0x0E, // [0] ConfirmedRequest, len=14
            0x02, 0x01, 0x01, // invokeID = 1
            0xA1, 0x09, // [1] GetNameList, len=9
            0xA0, 0x03, // [0] objectClass
            0x80, 0x01, 0x09, // [0] basicObjectClass IMPLICIT INT = 9 (domain)
            0xA1, 0x02, // [1] objectScope
            0x80, 0x00, // [0] vmdSpecific NULL
        ];
        let result = parse_mms_pdu(data).unwrap();
        match &result {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                service,
                get_name_list_info,
                ..
            } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::GetNameList);
                let info = get_name_list_info.as_ref().unwrap();
                assert_eq!(info.object_class.as_deref(), Some("domain"));
                assert_eq!(info.object_scope.as_deref(), Some("vmd_specific"));
                assert!(info.domain_id.is_none());
                assert!(info.continue_after.is_none());
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_get_name_list_request_domain_specific_with_continue_after() {
        // GetNameList Request: objectClass=named_variable(0),
        // objectScope=domainSpecific("LD1"), continueAfter="Var100"
        let data = &[
            0xA0, 0x19, // [0] ConfirmedRequest, len=25
            0x02, 0x01, 0x02, // invokeID = 2
            0xA1, 0x14, // [1] GetNameList, len=20
            0xA0, 0x03, // [0] objectClass
            0x80, 0x01, 0x00, // [0] basicObjectClass IMPLICIT INT = 0 (named_variable)
            0xA1, 0x05, // [1] objectScope
            0x81, 0x03, 0x4C, 0x44, 0x31, // [1] domainSpecific "LD1"
            0x82, 0x06, 0x56, 0x61, 0x72, 0x31, 0x30, 0x30, // [2] continueAfter "Var100"
        ];
        let result = parse_mms_pdu(data).unwrap();
        match &result {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                service,
                get_name_list_info,
                ..
            } => {
                assert_eq!(*invoke_id, 2);
                assert_eq!(*service, MmsConfirmedService::GetNameList);
                let info = get_name_list_info.as_ref().unwrap();
                assert_eq!(info.object_class.as_deref(), Some("named_variable"));
                assert_eq!(info.object_scope.as_deref(), Some("domain_specific"));
                assert_eq!(info.domain_id.as_deref(), Some("LD1"));
                assert_eq!(info.continue_after.as_deref(), Some("Var100"));
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_get_name_list_request_aa_specific() {
        // GetNameList Request: objectClass=named_variable_list(2), objectScope=aaSpecific
        let data = &[
            0xA0, 0x0E, // [0] ConfirmedRequest, len=14
            0x02, 0x01, 0x03, // invokeID = 3
            0xA1, 0x09, // [1] GetNameList, len=9
            0xA0, 0x03, // [0] objectClass
            0x80, 0x01, 0x02, // [0] basicObjectClass IMPLICIT INT = 2 (named_variable_list)
            0xA1, 0x02, // [1] objectScope
            0x82, 0x00, // [2] aaSpecific NULL
        ];
        let result = parse_mms_pdu(data).unwrap();
        match &result {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                service,
                get_name_list_info,
                ..
            } => {
                assert_eq!(*invoke_id, 3);
                assert_eq!(*service, MmsConfirmedService::GetNameList);
                let info = get_name_list_info.as_ref().unwrap();
                assert_eq!(info.object_class.as_deref(), Some("named_variable_list"));
                assert_eq!(info.object_scope.as_deref(), Some("aa_specific"));
                assert!(info.domain_id.is_none());
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_get_name_list_response_multiple_identifiers() {
        // GetNameList Response with 3 identifiers + moreFollows=true
        // listOfIdentifier inner: 3 * 6 = 18 bytes
        // [0] wrapper: 2 + 18 = 20 bytes
        // moreFollows: 3 bytes
        // service content: 20 + 3 = 23 bytes
        // service wrapper [1]: 2 + 23 = 25 bytes
        // invokeID: 3 bytes
        // total: 3 + 25 = 28 = 0x1C
        let data = &[
            0xA1, 0x1C, // [1] ConfirmedResponse, len=28
            0x02, 0x01, 0x01, // invokeID = 1
            0xA1, 0x17, // [1] GetNameList response, len=23
            0xA0, 0x12, // [0] listOfIdentifier, len=18
            0x1A, 0x04, 0x56, 0x61, 0x72, 0x31, // VisibleString "Var1"
            0x1A, 0x04, 0x56, 0x61, 0x72, 0x32, // VisibleString "Var2"
            0x1A, 0x04, 0x56, 0x61, 0x72, 0x33, // VisibleString "Var3"
            0x81, 0x01, 0xFF, // [1] moreFollows = TRUE
        ];
        let result = parse_mms_pdu(data).unwrap();
        match &result {
            MmsPdu::ConfirmedResponse {
                invoke_id,
                service,
                get_name_list_info,
                ..
            } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::GetNameList);
                let info = get_name_list_info.as_ref().unwrap();
                assert_eq!(info.identifiers, vec!["Var1", "Var2", "Var3"]);
                assert!(info.more_follows);
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    #[test]
    fn test_get_name_list_response_empty_list() {
        // GetNameList Response with empty list + moreFollows=false
        let data = &[
            0xA1, 0x0A, // [1] ConfirmedResponse
            0x02, 0x01, 0x02, // invokeID = 2
            0xA1, 0x05, // [1] GetNameList response
            0xA0, 0x00, // [0] listOfIdentifier (empty)
            0x81, 0x01, 0x00, // [1] moreFollows = FALSE
        ];
        let result = parse_mms_pdu(data).unwrap();
        match &result {
            MmsPdu::ConfirmedResponse {
                invoke_id,
                service,
                get_name_list_info,
                ..
            } => {
                assert_eq!(*invoke_id, 2);
                assert_eq!(*service, MmsConfirmedService::GetNameList);
                let info = get_name_list_info.as_ref().unwrap();
                assert!(info.identifiers.is_empty());
                assert!(!info.more_follows);
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    #[test]
    fn test_get_name_list_response_truncate_at_64() {
        // 直接测试 parse_get_name_list_response 内部函数确保截断到 64 条
        // 构造一个包含 100 个标识符的 listOfIdentifier
        let mut list_content = Vec::new();
        for i in 0..100u16 {
            // 每个 identifier: VisibleString tag=0x1A, len=2, content=两字节
            let hi = (i >> 8) as u8;
            let lo = (i & 0xFF) as u8;
            list_content.push(0x1A); // VisibleString tag
            list_content.push(0x02); // length=2
            list_content.push(hi);
            list_content.push(lo);
        }

        // 包装为 [0] listOfIdentifier
        let mut response_content = Vec::new();
        response_content.push(0xA0); // [0] constructed
        // 长格式长度编码 (list_content.len() = 100*4 = 400 = 0x0190)
        response_content.push(0x82);
        response_content.push(0x01);
        response_content.push(0x90);
        response_content.extend_from_slice(&list_content);

        let result = parse_get_name_list_response(&response_content, 0);
        assert_eq!(result.identifiers.len(), 64);
        assert!(result.more_follows); // 默认 true（无 moreFollows 字段时）
    }

    // ====== Initiate-Request/Response 深度解析测试 ======

    #[test]
    fn test_parse_confirmed_error_with_service_error() {
        // Confirmed-ErrorPDU [2]:
        //   invokeID = 5
        //   serviceError [2]:
        //     errorClass [0]:
        //       access [7] = 2 (object-non-existent)
        let data: &[u8] = &[
            0xA2, 0x0F, // [2] Confirmed-ErrorPDU, length=15
            0x80, 0x01, 0x05, // [0] invokeID = 5
            0xA2, 0x0A,       // [2] serviceError
            0xA0, 0x08,       //   [0] errorClass
            0x87, 0x01, 0x02, //     [7] access = 2 (object-non-existent)
            // 后续可能有 additionalCode 等，此处省略
            0x00, 0x00, 0x00, 0x00, 0x00, // padding (不影响解析)
        ];
        let result = parse_mms_pdu(data).unwrap();
        match result {
            MmsPdu::ConfirmedError { invoke_id, error_class, error_code } => {
                assert_eq!(invoke_id, 5);
                assert_eq!(error_class, Some("access".to_string()));
                assert_eq!(error_code, Some("object-non-existent".to_string()));
            }
            other => panic!("Expected ConfirmedError, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_confirmed_error_minimal() {
        // 仅含 invokeID，无 serviceError
        let data: &[u8] = &[
            0xA2, 0x03, // [2] Confirmed-ErrorPDU, length=3
            0x80, 0x01, 0x07, // [0] invokeID = 7
        ];
        let result = parse_mms_pdu(data).unwrap();
        match result {
            MmsPdu::ConfirmedError { invoke_id, error_class, error_code } => {
                assert_eq!(invoke_id, 7);
                assert_eq!(error_class, None);
                assert_eq!(error_code, None);
            }
            other => panic!("Expected ConfirmedError, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_confirmed_error_real_pcap() {
        // 从 mms.pcap frame 12 提取的真实 ConfirmedError PDU:
        // invokeID=303731, errorClass=access, errorCode=2 (hardware-fault)
        let data: &[u8] = &[
            0xA2, 0x0C,             // [2] Confirmed-ErrorPDU, length=12
            0x80, 0x03, 0x04, 0xA2, 0x73, // [0] invokeID = 303731
            0xA2, 0x05,             // [2] serviceError
            0xA0, 0x03,             //   [0] errorClass
            0x87, 0x01, 0x02,       //     [7] access = 2
        ];
        let result = parse_mms_pdu(data).unwrap();
        match result {
            MmsPdu::ConfirmedError { invoke_id, error_class, error_code } => {
                assert_eq!(invoke_id, 303731);
                assert_eq!(error_class, Some("access".to_string()));
                assert_eq!(error_code, Some("object-non-existent".to_string()));
            }
            other => panic!("Expected ConfirmedError, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_initiate_detail_all_fields() {
        // 构造完整的 Initiate-Request 内容（不含外层 tag/length），
        // 参照 libiec61850 mms_client_initiate.c:69-100 编码顺序：
        //   [0] 0x80 localDetailCalling = 65000 (0x00FDE8)
        //   [1] 0x81 maxServOutstandingCalling = 5
        //   [2] 0x82 maxServOutstandingCalled = 5
        //   [3] 0x83 dataStructureNestingLevel = 10
        //   [4] 0xA4 initRequestDetail SEQUENCE {
        //     [0] versionNumber = 1
        //     [1] parameterCBB = (bit string, 跳过)
        //     [2] servicesSupportedCalling = BIT STRING: 0x00(unused bits) + 0xEE 0x1C
        //   }
        let content: &[u8] = &[
            0x80, 0x03, 0x00, 0xFD, 0xE8, // [0] localDetail = 65000
            0x81, 0x01, 0x05,             // [1] maxServOutstandingCalling = 5
            0x82, 0x01, 0x05,             // [2] maxServOutstandingCalled = 5
            0x83, 0x01, 0x0A,             // [3] nestingLevel = 10
            0xA4, 0x0D,                   // [4] initRequestDetail
                0x80, 0x01, 0x01,         //   [0] versionNumber = 1
                0x81, 0x03, 0x00, 0xFB, 0x00, //   [1] parameterCBB (ignored)
                0x82, 0x03, 0x00, 0xEE, 0x1C, //   [2] servicesSupportedCalling (BIT STRING: 0 unused + EE 1C)
        ];
        let detail = parse_initiate_detail(content, 0);
        assert_eq!(detail.local_detail, Some(65000));
        assert_eq!(detail.max_serv_outstanding_calling, Some(5));
        assert_eq!(detail.max_serv_outstanding_called, Some(5));
        assert_eq!(detail.data_structure_nesting_level, Some(10));
        assert_eq!(detail.version_number, Some(1));
        assert_eq!(detail.supported_services, Some(vec![0xEE, 0x1C]));
    }

    #[test]
    fn test_parse_initiate_detail_partial() {
        // 仅包含 [0] localDetail，无其他字段
        let content: &[u8] = &[
            0x80, 0x02, 0x04, 0x00, // [0] localDetail = 1024
        ];
        let detail = parse_initiate_detail(content, 0);
        assert_eq!(detail.local_detail, Some(1024));
        assert_eq!(detail.max_serv_outstanding_calling, None);
        assert_eq!(detail.max_serv_outstanding_called, None);
        assert_eq!(detail.data_structure_nesting_level, None);
        assert_eq!(detail.version_number, None);
        assert_eq!(detail.supported_services, None);
    }

    #[test]
    fn test_parse_initiate_detail_empty() {
        let detail = parse_initiate_detail(&[], 0);
        assert_eq!(detail, MmsInitDetail::default());
    }

    #[test]
    fn test_parse_mms_pdu_initiate_request_full() {
        // 完整 Initiate-Request PDU，参照 libiec61850 编码顺序
        let data: &[u8] = &[
            0xA8, 0x16, // [8] Initiate-Request, length=22
            0x80, 0x02, 0x04, 0x00, // [0] localDetail = 1024
            0x81, 0x01, 0x05,       // [1] maxServOutstandingCalling = 5
            0x82, 0x01, 0x05,       // [2] maxServOutstandingCalled = 5
            0x83, 0x01, 0x04,       // [3] nestingLevel = 4
            0xA4, 0x07,             // [4] initRequestDetail
                0x80, 0x01, 0x01,   //   [0] versionNumber = 1
                0x82, 0x02, 0x00, 0xFF, //   [2] servicesSupportedCalling (BIT STRING: 0 unused bits + 0xFF)
        ];
        let result = parse_mms_pdu(data).unwrap();
        match result {
            MmsPdu::InitiateRequest { detail } => {
                let d = detail.unwrap();
                assert_eq!(d.local_detail, Some(1024));
                assert_eq!(d.max_serv_outstanding_calling, Some(5));
                assert_eq!(d.max_serv_outstanding_called, Some(5));
                assert_eq!(d.data_structure_nesting_level, Some(4));
                assert_eq!(d.version_number, Some(1));
                assert_eq!(d.supported_services, Some(vec![0xFF]));
            }
            other => panic!("Expected InitiateRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_mms_pdu_initiate_response_full() {
        let data: &[u8] = &[
            0xA9, 0x0F, // [9] Initiate-Response, length=15
            0x80, 0x02, 0x08, 0x00, // [0] localDetail = 2048
            0x81, 0x01, 0x05,       // [1] maxServOutstandingCalling = 5
            0x82, 0x01, 0x05,       // [2] maxServOutstandingCalled = 5
            0xA4, 0x03,             // [4] initResponseDetail
                0x80, 0x01, 0x01,   //   [0] versionNumber = 1
        ];
        let result = parse_mms_pdu(data).unwrap();
        match result {
            MmsPdu::InitiateResponse { detail } => {
                let d = detail.unwrap();
                assert_eq!(d.local_detail, Some(2048));
                assert_eq!(d.max_serv_outstanding_calling, Some(5));
                assert_eq!(d.max_serv_outstanding_called, Some(5));
                assert_eq!(d.data_structure_nesting_level, None);
                assert_eq!(d.version_number, Some(1));
            }
            other => panic!("Expected InitiateResponse, got {:?}", other),
        }
    }

    // ====== GetVariableAccessAttributes Request 深度解析测试 ======

    #[test]
    fn test_get_var_access_attr_vmd_specific() {
        let data: &[u8] = &[
            0xA0, 0x0B, // [0] ConfirmedRequest
            0x02, 0x01, 0x01, // invokeID = 1
            0xA6, 0x06, // [6] GetVariableAccessAttributes
            0xA0, 0x04, // [0] name
            0x80, 0x02, 0x6D, 0x75, // [0] vmd-specific "mu"
        ];
        let result = parse_mms_pdu(data).unwrap();
        match &result {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                service,
                get_var_access_attr_info,
                ..
            } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::GetVariableAccessAttributes);
                let info = get_var_access_attr_info.as_ref().unwrap();
                assert_eq!(
                    info.object_name,
                    Some(ObjectNameRef::VmdSpecific("mu".to_string()))
                );
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_get_var_access_attr_domain_specific() {
        let data: &[u8] = &[
            0xA0, 0x16, // [0] ConfirmedRequest
            0x02, 0x01, 0x02, // invokeID = 2
            0xA6, 0x11, // [6] GetVariableAccessAttributes
            0xA0, 0x0F, // [0] name
            0xA1, 0x0D, // [1] domain-specific
            0x1A, 0x04, 0x4C, 0x44, 0x30, 0x31, // VisibleString "LD01"
            0x1A, 0x05, 0x56, 0x61, 0x6C, 0x75, 0x65, // VisibleString "Value"
        ];
        let result = parse_mms_pdu(data).unwrap();
        match &result {
            MmsPdu::ConfirmedRequest {
                get_var_access_attr_info,
                ..
            } => {
                let info = get_var_access_attr_info.as_ref().unwrap();
                assert_eq!(
                    info.object_name,
                    Some(ObjectNameRef::DomainSpecific {
                        domain_id: "LD01".to_string(),
                        item_id: "Value".to_string(),
                    })
                );
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_get_var_access_attr_aa_specific() {
        let data: &[u8] = &[
            0xA0, 0x0A, // [0] ConfirmedRequest
            0x02, 0x01, 0x03, // invokeID = 3
            0xA6, 0x05, // [6] GetVariableAccessAttributes
            0xA0, 0x03, // [0] name
            0x82, 0x01, 0x78, // [2] aa-specific "x"
        ];
        let result = parse_mms_pdu(data).unwrap();
        match &result {
            MmsPdu::ConfirmedRequest {
                get_var_access_attr_info,
                ..
            } => {
                let info = get_var_access_attr_info.as_ref().unwrap();
                assert_eq!(
                    info.object_name,
                    Some(ObjectNameRef::AaSpecific("x".to_string()))
                );
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    // ─── GetNamedVariableListAttributes tests ───

    #[test]
    fn test_parse_get_named_var_list_attr_request_domain_specific() {
        // ConfirmedRequest { invokeID=1, getNamedVariableListAttributes(12): domain-specific { "DOM1", "DS1" } }
        let data: Vec<u8> = vec![
            0xA0, 22,       // ConfirmedRequestPDU [0]
            0x02, 1, 1,     // invokeID = 1
            0xAC, 17,       // [12] getNamedVariableListAttributes
            // ObjectName: domain-specific [1] SEQUENCE
            0xA1, 15,
            0x1A, 4, b'D', b'O', b'M', b'1',  // domainId = "DOM1"
            0x1A, 7, b'L', b'L', b'N', b'0', b'$', b'D', b'S',  // itemId = "LLN0$DS"
        ];
        let result = parse_mms_pdu(&data);
        assert!(result.is_ok());
        match &result.unwrap() {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                service,
                get_named_var_list_attr_info,
                ..
            } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::GetNamedVariableListAttributes);
                let info = get_named_var_list_attr_info.as_ref().unwrap();
                assert_eq!(
                    info.object_name,
                    Some(ObjectNameRef::DomainSpecific {
                        domain_id: "DOM1".to_string(),
                        item_id: "LLN0$DS".to_string(),
                    })
                );
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_get_named_var_list_attr_request_vmd_specific() {
        // ConfirmedRequest { invokeID=2, getNamedVariableListAttributes(12): vmd-specific "MyDS" }
        let data: Vec<u8> = vec![
            0xA0, 11,       // ConfirmedRequestPDU [0]
            0x02, 1, 2,     // invokeID = 2
            0xAC, 6,        // [12] getNamedVariableListAttributes
            // ObjectName: vmd-specific [0] IMPLICIT Identifier
            0x80, 4, b'M', b'y', b'D', b'S',
        ];
        let result = parse_mms_pdu(&data);
        assert!(result.is_ok());
        match &result.unwrap() {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                get_named_var_list_attr_info,
                ..
            } => {
                assert_eq!(*invoke_id, 2);
                let info = get_named_var_list_attr_info.as_ref().unwrap();
                assert_eq!(
                    info.object_name,
                    Some(ObjectNameRef::VmdSpecific("MyDS".to_string()))
                );
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_get_named_var_list_attr_response() {
        // ConfirmedResponse { invokeID=1, getNamedVariableListAttributes(12):
        //   mmsDeletable=false, listOfVariable=[ domain-specific("D","V1"), domain-specific("D","V2") ] }
        //
        // item内层: 0xA1,8, 0x1A,1,'D', 0x1A,3,'V','_','x' = 10字节 (domain-specific)
        // name层:   0xA0,10, ... = 12字节
        // item SEQUENCE: 0x30,12, ... = 14字节
        // 两个item = 28字节
        // listOfVariable: 0xA1,28, ... = 30字节
        // mmsDeletable: 0x80,1,0x00 = 3字节
        // service content = 33字节
        // service tag: 0xAC,33, ... = 35字节
        // invokeID: 0x02,1,1 = 3字节
        // total content = 38字节
        let data: Vec<u8> = vec![
            0xA1, 38,       // ConfirmedResponsePDU [1]
            0x02, 1, 1,     // invokeID = 1
            0xAC, 33,       // [12] getNamedVariableListAttributes
            // mmsDeletable [0] IMPLICIT BOOLEAN = FALSE
            0x80, 1, 0x00,
            // listOfVariable [1] IMPLICIT SEQUENCE OF
            0xA1, 28,
            // item 1: SEQUENCE { variableSpecification: name [0] ObjectName }
            0x30, 12,
            0xA0, 10,       // name [0]
            0xA1, 8,        // domain-specific [1]
            0x1A, 1, b'D',  // domainId = "D"
            0x1A, 3, b'V', b'_', b'1', // itemId = "V_1"
            // item 2
            0x30, 12,
            0xA0, 10,       // name [0]
            0xA1, 8,        // domain-specific [1]
            0x1A, 1, b'D',  // domainId = "D"
            0x1A, 3, b'V', b'_', b'2', // itemId = "V_2"
        ];
        let result = parse_mms_pdu(&data);
        assert!(result.is_ok());
        match &result.unwrap() {
            MmsPdu::ConfirmedResponse {
                invoke_id,
                service,
                get_named_var_list_attr_info,
                ..
            } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::GetNamedVariableListAttributes);
                let info = get_named_var_list_attr_info.as_ref().unwrap();
                assert_eq!(info.mms_deletable, false);
                assert_eq!(info.variables.len(), 2);
                assert_eq!(
                    info.variables[0],
                    ObjectNameRef::DomainSpecific {
                        domain_id: "D".to_string(),
                        item_id: "V_1".to_string(),
                    }
                );
                assert_eq!(
                    info.variables[1],
                    ObjectNameRef::DomainSpecific {
                        domain_id: "D".to_string(),
                        item_id: "V_2".to_string(),
                    }
                );
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    // ====== parse_read_response 数据类型覆盖测试 ======
    //
    // tag byte 参照 ISO 9506-2 Data CHOICE（libiec61850 mms_access_result.c 验证）：
    //   0x80  failure (DataAccessError)
    //   0xA1  [1] array (constructed)
    //   0xA2  [2] structure (constructed)
    //   0x83  [3] boolean
    //   0x84  [4] bit-string
    //   0x85  [5] integer
    //   0x86  [6] unsigned
    //   0x87  [7] floating-point
    //   0x89  [9] octet-string
    //   0x8A  [10] visible-string
    //   0x8C  [12] binary-time
    //   0x90  [16] mms-string
    //   0x91  [17] utc-time

    /// 辅助函数：将一组 AccessResult 条目字节包装成 [0] listOfAccessResult 结构，
    /// 然后调用 parse_read_response 返回解析结果。
    fn read_response_from_items(items: &[u8]) -> MmsReadResponse {
        let mut content = Vec::new();
        content.push(0xA0); // [0] listOfAccessResult
        let len = items.len();
        if len < 128 {
            content.push(len as u8);
        } else {
            content.push(0x82);
            content.push((len >> 8) as u8);
            content.push((len & 0xFF) as u8);
        }
        content.extend_from_slice(items);
        parse_read_response(&content, 0)
    }

    // --- boolean [3] tag=0x83 ---

    #[test]
    fn test_read_response_boolean_true() {
        let items = [0x83, 0x01, 0xFF]; // [3] boolean = true
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("boolean"));
        assert_eq!(r.value.as_deref(), Some("true"));
    }

    #[test]
    fn test_read_response_boolean_false() {
        let items = [0x83, 0x01, 0x00]; // [3] boolean = false
        let resp = read_response_from_items(&items);
        assert_eq!(resp.results[0].value.as_deref(), Some("false"));
    }

    #[test]
    fn test_read_response_boolean_empty() {
        let items = [0x83, 0x00]; // [3] boolean 空内容 → None
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("boolean"));
        assert!(r.value.is_none());
    }

    // --- bit-string [4] tag=0x84 → hex 兜底 ---

    #[test]
    fn test_read_response_bit_string() {
        let items = [0x84, 0x03, 0x00, 0xFB, 0x00]; // [4] bit-string
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("bit-string"));
        assert_eq!(r.value.as_deref(), Some("00fb00")); // hex 兜底
    }

    // --- integer [5] tag=0x85 ---

    #[test]
    fn test_read_response_integer() {
        let items = [0x85, 0x02, 0x01, 0x00]; // [5] integer = 256
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("integer"));
        assert_eq!(r.value.as_deref(), Some("256"));
    }

    #[test]
    fn test_read_response_integer_negative() {
        // [5] integer = -1, BER 编码: 0xFF
        let items = [0x85, 0x01, 0xFF];
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("integer"));
        assert_eq!(r.value.as_deref(), Some("-1"));
    }

    #[test]
    fn test_read_response_integer_negative_two_bytes() {
        // [5] integer = -256, BER 编码: 0xFF 0x00
        let items = [0x85, 0x02, 0xFF, 0x00];
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.value.as_deref(), Some("-256"));
    }

    #[test]
    fn test_read_response_integer_negative_128() {
        // [5] integer = -128, BER 编码: 0x80
        let items = [0x85, 0x01, 0x80];
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.value.as_deref(), Some("-128"));
    }

    // --- unsigned [6] tag=0x86 ---

    #[test]
    fn test_read_response_unsigned() {
        let items = [0x86, 0x01, 0x2A]; // [6] unsigned = 42
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("unsigned"));
        assert_eq!(r.value.as_deref(), Some("42"));
    }

    // --- floating-point [7] tag=0x87 ---

    #[test]
    fn test_read_response_float_single_precision() {
        // [7] floating-point: 1 byte exponent width + 4 bytes IEEE 754 float
        let float_bytes = 1.0_f32.to_be_bytes();
        let items = [
            0x87, 0x05, 0x08, // tag=[7], length=5, exponent=8
            float_bytes[0], float_bytes[1], float_bytes[2], float_bytes[3],
        ];
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("floating-point"));
        assert!(r.value.as_ref().unwrap().contains("1"));
    }

    #[test]
    fn test_read_response_float_double_precision() {
        // [7] floating-point: 1 byte exponent width + 8 bytes IEEE 754 double
        let double_bytes = 3.14_f64.to_be_bytes();
        let mut items = vec![0x87, 0x09, 0x0B]; // tag=[7], length=9, exponent=11
        items.extend_from_slice(&double_bytes);
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("floating-point"));
        assert!(r.value.as_ref().unwrap().starts_with("3.14"));
    }

    #[test]
    fn test_read_response_float_abnormal_length_3() {
        let items = [0x87, 0x03, 0x08, 0x40, 0x00]; // 3 字节 → None
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("floating-point"));
        assert!(r.value.is_none());
    }

    #[test]
    fn test_read_response_float_abnormal_length_7() {
        let items = [0x87, 0x07, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]; // 7 字节 → None
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("floating-point"));
        assert!(r.value.is_none());
    }

    #[test]
    fn test_read_response_float_empty() {
        let items = [0x87, 0x00]; // 0 字节 → None
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("floating-point"));
        assert!(r.value.is_none());
    }

    // --- octet-string [9] tag=0x89 → string ---

    #[test]
    fn test_read_response_octet_string() {
        let items = [0x89, 0x03, 0x41, 0x42, 0x43]; // [9] octet-string "ABC"
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("octet-string"));
        assert_eq!(r.value.as_deref(), Some("ABC"));
    }

    // --- visible-string [10] tag=0x8A → string ---

    #[test]
    fn test_read_response_visible_string() {
        let items = [0x8A, 0x05, b'H', b'e', b'l', b'l', b'o']; // [10] "Hello"
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("visible-string"));
        assert_eq!(r.value.as_deref(), Some("Hello"));
    }

    // --- binary-time [12] tag=0x8C → hex 兜底 ---

    #[test]
    fn test_read_response_binary_time() {
        let items = [0x8C, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]; // [12]
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("binary-time"));
        assert_eq!(r.value.as_deref(), Some("010203040506"));
    }

    // --- mms-string [16] tag=0x90 → string ---

    #[test]
    fn test_read_response_mms_string() {
        let items = [0x90, 0x04, 0xC3, 0xA9, 0x6C, 0x6F]; // [16] UTF-8 "élo"
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("mms-string"));
        assert_eq!(r.value.as_deref(), Some("élo"));
    }

    // --- utc-time [17] tag=0x91 → hex 兜底 ---

    #[test]
    fn test_read_response_utc_time() {
        // [17] UTC-Time: 8 字节
        let items = [0x91, 0x08, 0x5A, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A];
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("utc-time"));
        assert_eq!(r.value.as_deref(), Some("5a0000010000000a"));
    }

    // --- hex 兜底：空内容 → value=None ---

    #[test]
    fn test_read_response_hex_fallback_empty() {
        let items = [0x84, 0x00]; // [4] bit-string 空内容
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("bit-string"));
        assert!(r.value.is_none());
    }

    // --- 未知 tag_num → data_type=None ---

    #[test]
    fn test_read_response_unknown_data_tag() {
        let items = [0x8F, 0x01, 0xAB]; // tag_num=15, 不在 data_tag_name 映射中
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert!(r.data_type.is_none());
        assert_eq!(r.value.as_deref(), Some("ab"));
    }

    // ====== 多条目 + 截断测试 ======

    #[test]
    fn test_read_response_multiple_mixed_types() {
        let items = [
            0x80, 0x01, 0x02,       // failure: error=2
            0x83, 0x01, 0x01,       // [3] boolean: true
            0x86, 0x01, 0x2A,       // [6] unsigned: 42
        ];
        let resp = read_response_from_items(&items);
        assert_eq!(resp.results.len(), 3);
        // failure
        assert!(!resp.results[0].success);
        assert_eq!(resp.results[0].data_type.as_deref(), Some("error"));
        assert_eq!(resp.results[0].value.as_deref(), Some("2"));
        // boolean
        assert!(resp.results[1].success);
        assert_eq!(resp.results[1].data_type.as_deref(), Some("boolean"));
        assert_eq!(resp.results[1].value.as_deref(), Some("true"));
        // unsigned
        assert!(resp.results[2].success);
        assert_eq!(resp.results[2].data_type.as_deref(), Some("unsigned"));
        assert_eq!(resp.results[2].value.as_deref(), Some("42"));
    }

    #[test]
    fn test_read_response_truncate_at_64() {
        let mut items = Vec::new();
        for i in 0u8..70 {
            items.push(0x86); // [6] unsigned
            items.push(0x01);
            items.push(i);
        }
        let resp = read_response_from_items(&items);
        assert_eq!(resp.results.len(), 64);
        assert_eq!(resp.results[63].value.as_deref(), Some("63"));
    }

    // ====== structure / array 成员计数测试 ======

    #[test]
    fn test_read_response_structure_member_count() {
        // [2] structure (constructed), tag=0xA2
        // 内部 3 个元素（用正确 tag）
        let items = [
            0xA2, 0x09,             // structure, length=9
            0x83, 0x01, 0x01,       //   [3] boolean
            0x85, 0x01, 0x05,       //   [5] integer
            0x86, 0x01, 0x0A,       //   [6] unsigned
        ];
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("structure"));
        assert_eq!(r.value.as_deref(), Some("3 items"));
    }

    #[test]
    fn test_read_response_array_empty() {
        let items = [0xA1, 0x00]; // [1] array (constructed), 空
        let resp = read_response_from_items(&items);
        let r = &resp.results[0];
        assert!(r.success);
        assert_eq!(r.data_type.as_deref(), Some("array"));
        assert_eq!(r.value.as_deref(), Some("0 items"));
    }

    // ====== Write Request 解析测试 ======

    #[test]
    fn test_parse_write_request_domain_specific() {
        // ConfirmedRequest: Write with domain-specific variable LLN0/Mod
        // WriteRequest ::= SEQUENCE {
        //   variableAccessSpecification VariableAccessSpecification,
        //   listOfData [0] IMPLICIT SEQUENCE OF Data
        // }
        let data = &[
            0xA0, 0x1D, // [0] ConfirmedRequest, length=29
            0x02, 0x01, 0x01, // INTEGER invokeID = 1
            0xA5, 0x18, // [5] Write, length=24
            // variableAccessSpecification: listOfVariable [0]
            0xA0, 0x11, // [0] listOfVariable, length=17
            0x30, 0x0F, // SEQUENCE, length=15
            0xA0, 0x0D, // [0] name (VariableSpecification)
            0xA1, 0x0B, // [1] domain-specific
            0x1A, 0x04, 0x4C, 0x4C, 0x4E, 0x30, // VisibleString "LLN0"
            0x1A, 0x03, 0x4D, 0x6F, 0x64,       // VisibleString "Mod"
            // listOfData [0] IMPLICIT SEQUENCE OF Data
            0xA0, 0x03, // [0] listOfData, length=3
            0x83, 0x01, 0x01, // boolean true
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok(), "parse_mms_pdu failed: {:?}", result);
        let pdu = result.unwrap();
        match &pdu {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                service,
                write_info,
                ..
            } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::Write);
                assert!(write_info.is_some(), "write_info should be Some");
                let wi = write_info.as_ref().unwrap();
                assert_eq!(wi.variable_specs.len(), 1);
                assert_eq!(
                    wi.variable_specs[0],
                    ObjectNameRef::DomainSpecific {
                        domain_id: "LLN0".to_string(),
                        item_id: "Mod".to_string(),
                    }
                );
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_write_request_vmd_specific() {
        // Write with vmd-specific variable "Var1"
        let data = &[
            0xA0, 0x16, // [0] ConfirmedRequest, length=22
            0x02, 0x01, 0x01, // INTEGER invokeID = 1
            0xA5, 0x11, // [5] Write, length=17
            // variableAccessSpecification: listOfVariable [0]
            0xA0, 0x0A, // [0] listOfVariable, length=10
            0x30, 0x08, // SEQUENCE, length=8
            0xA0, 0x06, // [0] name (VariableSpecification)
            0x80, 0x04, 0x56, 0x61, 0x72, 0x31, // [0] vmd-specific "Var1"
            // listOfData [0] IMPLICIT SEQUENCE OF Data
            0xA0, 0x03, // [0] listOfData, length=3
            0x83, 0x01, 0x01, // boolean true
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok(), "parse_mms_pdu failed: {:?}", result);
        let pdu = result.unwrap();
        match &pdu {
            MmsPdu::ConfirmedRequest {
                invoke_id,
                service,
                write_info,
                ..
            } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::Write);
                assert!(write_info.is_some(), "write_info should be Some");
                let wi = write_info.as_ref().unwrap();
                assert_eq!(wi.variable_specs.len(), 1);
                assert_eq!(
                    wi.variable_specs[0],
                    ObjectNameRef::VmdSpecific("Var1".to_string())
                );
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_write_request_truncate_at_64() {
        // 构造含 70 个 vmd_specific 变量的 Write 请求，验证截断到 64 条
        // 每个变量 "V" = 1 字节：
        //   SEQUENCE: 30 05 A0 03 80 01 56 = 7 bytes per variable
        let var_spec: [u8; 7] = [
            0x30, 0x05, // SEQUENCE, length=5
            0xA0, 0x03, // [0] name
            0x80, 0x01, 0x56, // [0] vmd-specific "V"
        ];
        let var_count = 70usize;

        // listOfVariable [0] inner = var_count * 7 bytes
        let list_inner_len = var_count * 7;
        let mut list_of_var = vec![0xA0]; // [0] listOfVariable tag
        // BER 长度编码（长形式 2 字节）
        list_of_var.push(0x82);
        list_of_var.push(((list_inner_len >> 8) & 0xFF) as u8);
        list_of_var.push((list_inner_len & 0xFF) as u8);
        for _ in 0..var_count {
            list_of_var.extend_from_slice(&var_spec);
        }

        // listOfData [0] 最简：一个 boolean
        let list_of_data: [u8; 5] = [0xA0, 0x03, 0x83, 0x01, 0x01];

        // Write service content = listOfVariable + listOfData
        let mut write_content = Vec::new();
        write_content.extend_from_slice(&list_of_var);
        write_content.extend_from_slice(&list_of_data);

        // [5] Write tag
        let mut write_tlv = vec![0xA5];
        let wlen = write_content.len();
        write_tlv.push(0x82);
        write_tlv.push(((wlen >> 8) & 0xFF) as u8);
        write_tlv.push((wlen & 0xFF) as u8);
        write_tlv.extend_from_slice(&write_content);

        // invokeID
        let invoke_id: [u8; 3] = [0x02, 0x01, 0x01];

        // ConfirmedRequest [0]
        let inner_len = invoke_id.len() + write_tlv.len();
        let mut data = vec![0xA0];
        data.push(0x82);
        data.push(((inner_len >> 8) & 0xFF) as u8);
        data.push((inner_len & 0xFF) as u8);
        data.extend_from_slice(&invoke_id);
        data.extend_from_slice(&write_tlv);

        let result = parse_mms_pdu(&data);
        assert!(result.is_ok());
        let pdu = result.unwrap();
        match &pdu {
            MmsPdu::ConfirmedRequest { write_info, .. } => {
                let wi = write_info.as_ref().expect("write_info should be Some");
                assert_eq!(wi.variable_specs.len(), 64,
                    "Should truncate to 64, got {}", wi.variable_specs.len());
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_write_request_malformed_no_panic() {
        // 各种畸形 Write 请求数据，都不应该 panic
        let cases: Vec<&[u8]> = vec![
            // 空的 Write service content
            &[0xA0, 0x05, 0x02, 0x01, 0x01, 0xA5, 0x00],
            // Write 内容被截断
            &[0xA0, 0x06, 0x02, 0x01, 0x01, 0xA5, 0x01, 0xA0],
            // listOfVariable 长度声明大于实际数据
            &[0xA0, 0x08, 0x02, 0x01, 0x01, 0xA5, 0x03, 0xA0, 0xFF, 0x00],
            // listOfVariable 内容为垃圾
            &[0xA0, 0x0A, 0x02, 0x01, 0x01, 0xA5, 0x05, 0xA0, 0x03, 0xFF, 0xFF, 0xFF],
            // 仅 invokeID 无服务数据
            &[0xA0, 0x03, 0x02, 0x01, 0x01],
        ];
        for (i, data) in cases.iter().enumerate() {
            // 不 panic 就算通过，结果可以是 Ok 或 Err
            let _ = parse_mms_pdu(data);
            // 如果解析成功且是 Write，write_info 可以是 None（没解析出变量）
            if let Ok(MmsPdu::ConfirmedRequest { write_info, .. }) = parse_mms_pdu(data) {
                if let Some(wi) = write_info {
                    // 即使解析出了什么，变量列表也不应该包含垃圾
                    assert!(wi.variable_specs.len() <= 64,
                        "Case {}: too many specs", i);
                }
            }
        }
    }

    // ====== Write Request listOfData 解析测试 ======

    #[test]
    fn test_parse_write_request_with_boolean_data() {
        // Write with vmd-specific variable "V" + listOfData containing boolean true
        let data = &[
            0xA0, 0x13, // [0] ConfirmedRequest, length=19
            0x02, 0x01, 0x01, // INTEGER invokeID = 1
            0xA5, 0x0E, // [5] Write, length=14
            // variableAccessSpecification: listOfVariable [0]
            0xA0, 0x07, // [0] listOfVariable, length=7
            0x30, 0x05, // SEQUENCE, length=5
            0xA0, 0x03, // [0] name
            0x80, 0x01, 0x56, // [0] vmd-specific "V"
            // listOfData [0] IMPLICIT SEQUENCE OF Data
            0xA0, 0x03, // [0] listOfData, length=3
            0x83, 0x01, 0x01, // [3] boolean true
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok(), "parse_mms_pdu failed: {:?}", result);
        let pdu = result.unwrap();
        match &pdu {
            MmsPdu::ConfirmedRequest { write_info, .. } => {
                let wi = write_info.as_ref().expect("write_info should be Some");
                assert_eq!(wi.variable_specs.len(), 1);
                assert_eq!(wi.data.len(), 1, "should have 1 data item");
                let d = &wi.data[0];
                assert!(d.success);
                assert_eq!(d.data_type.as_deref(), Some("boolean"));
                assert_eq!(d.value.as_deref(), Some("true"));
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_write_request_with_structure_data() {
        // Write with vmd-specific variable "V" + listOfData containing structure with 3 members
        // structure [2] = tag 0xA2 (constructed)
        // 3 members: boolean true, integer 5, unsigned 10
        let data = &[
            0xA0, 0x22, // [0] ConfirmedRequest, length=34
            0x02, 0x01, 0x01, // INTEGER invokeID = 1
            0xA5, 0x1D, // [5] Write, length=29
            // variableAccessSpecification: listOfVariable [0]
            0xA0, 0x07, // [0] listOfVariable, length=7
            0x30, 0x05, // SEQUENCE
            0xA0, 0x03, // [0] name
            0x80, 0x01, 0x56, // vmd-specific "V"
            // listOfData [0]
            0xA0, 0x12, // [0] listOfData, length=18
            // structure [2] with 3 members
            0xA2, 0x10, // [2] structure, length=16
            0x83, 0x01, 0x01, // boolean true (3 bytes)
            0x85, 0x01, 0x05, // integer 5 (3 bytes)
            0x86, 0x01, 0x0A, // unsigned 10 (3 bytes)
            // padding to make structure content valid - wait, 3*3=9, structure length should be 9
        ];
        // Recalculate: structure inner = 9 bytes, so tag A2 09
        // listOfData inner = A2 09 ... = 11 bytes, so tag A0 0B
        // Write inner = A0 07 ... + A0 0B ... = 7+2 + 11+2 = 22 bytes? No.
        // listOfVariable = A0 07 (2 + 7 inner = 9 bytes total)
        // listOfData = A0 0B (2 + 11 inner? no)
        // Let me be more careful:
        // structure content: 83 01 01  85 01 05  86 01 0A = 9 bytes
        // structure TLV: A2 09 <9 bytes> = 11 bytes
        // listOfData content: 11 bytes
        // listOfData TLV: A0 0B <11 bytes> = 13 bytes
        // listOfVariable TLV: A0 07 <7 bytes inner> = 9 bytes
        // Write content: 9 + 13 = 22 bytes
        // Write TLV: A5 16 <22 bytes> = 24 bytes
        // invokeID: 02 01 01 = 3 bytes
        // ConfirmedRequest content: 3 + 24 = 27 bytes
        // ConfirmedRequest TLV: A0 1B <27 bytes>
        let data = &[
            0xA0, 0x1B, // [0] ConfirmedRequest, length=27
            0x02, 0x01, 0x01, // invokeID = 1
            0xA5, 0x16, // [5] Write, length=22
            // listOfVariable [0]
            0xA0, 0x07,
            0x30, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x56,
            // listOfData [0]
            0xA0, 0x0B,
            // structure [2] with 3 members
            0xA2, 0x09,
            0x83, 0x01, 0x01, // boolean true
            0x85, 0x01, 0x05, // integer 5
            0x86, 0x01, 0x0A, // unsigned 10
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok(), "parse_mms_pdu failed: {:?}", result);
        match &result.unwrap() {
            MmsPdu::ConfirmedRequest { write_info, .. } => {
                let wi = write_info.as_ref().expect("write_info should be Some");
                assert_eq!(wi.data.len(), 1);
                let d = &wi.data[0];
                assert!(d.success);
                assert_eq!(d.data_type.as_deref(), Some("structure"));
                assert_eq!(d.value.as_deref(), Some("3 items"));
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_parse_write_request_with_integer_unsigned_data() {
        // Write with vmd-specific variable "V" + listOfData containing integer(-3) and unsigned(42)
        // integer [5] = tag 0x85, unsigned [6] = tag 0x86
        // integer -3: 0x85 0x01 0xFD
        // unsigned 42: 0x86 0x01 0x2A
        // listOfData inner: 3 + 3 = 6 bytes
        // listOfData TLV: A0 06 = 8 bytes
        // listOfVariable TLV: A0 07 = 9 bytes
        // Write content: 9 + 8 = 17 bytes → A5 11
        // invokeID: 3 bytes
        // ConfirmedRequest content: 3 + 19 = 22 → A0 16? No.
        // Write TLV = A5 11 = 2 + 17 = 19 bytes total
        // ConfirmedRequest content = 3 + 19 = 22 → A0 16
        let data = &[
            0xA0, 0x16, // [0] ConfirmedRequest, length=22
            0x02, 0x01, 0x01, // invokeID = 1
            0xA5, 0x11, // [5] Write, length=17
            // listOfVariable [0]
            0xA0, 0x07,
            0x30, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x56,
            // listOfData [0]
            0xA0, 0x06,
            0x85, 0x01, 0xFD, // integer -3
            0x86, 0x01, 0x2A, // unsigned 42
        ];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok(), "parse_mms_pdu failed: {:?}", result);
        match &result.unwrap() {
            MmsPdu::ConfirmedRequest { write_info, .. } => {
                let wi = write_info.as_ref().expect("write_info should be Some");
                assert_eq!(wi.data.len(), 2, "should have 2 data items");
                // integer -3
                let d0 = &wi.data[0];
                assert!(d0.success);
                assert_eq!(d0.data_type.as_deref(), Some("integer"));
                assert_eq!(d0.value.as_deref(), Some("-3"));
                // unsigned 42
                let d1 = &wi.data[1];
                assert!(d1.success);
                assert_eq!(d1.data_type.as_deref(), Some("unsigned"));
                assert_eq!(d1.value.as_deref(), Some("42"));
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    // ====== Write Response 解析测试 ======

    #[test]
    fn test_write_response_all_success() {
        // ConfirmedResponse with Write service: 2 个 success
        // invokeID: 02 01 01 = 3 bytes
        // Write [5]: A5 04 (inner=4: 81 00 + 81 00)
        // Total inner = 3 + 6 = 9 → A1 09
        let data = &[
            0xA1, 0x09, // [1] len=9
            0x02, 0x01, 0x01, // invokeID = 1
            0xA5, 0x04, // [5] Write, len=4
            0x81, 0x00, // success [1] NULL
            0x81, 0x00, // success [1] NULL
        ];
        let pdu = parse_mms_pdu(data).expect("should parse");
        match &pdu {
            MmsPdu::ConfirmedResponse { invoke_id, service, write_info, .. } => {
                assert_eq!(*invoke_id, 1);
                assert_eq!(*service, MmsConfirmedService::Write);
                let wi = write_info.as_ref().expect("write_info should be Some");
                assert_eq!(wi.results.len(), 2);
                assert!(wi.results[0].success);
                assert!(wi.results[0].error.is_none());
                assert!(wi.results[1].success);
                assert!(wi.results[1].error.is_none());
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    #[test]
    fn test_write_response_partial_failure() {
        // Write response: success, failure(object-access-denied=3), success
        // invokeID: 02 01 02 = 3 bytes
        // Write [5]: A5 07 (inner=7: 81 00 + 80 01 03 + 81 00)
        // Total inner = 3 + 9 = 12 → A1 0C
        let data = &[
            0xA1, 0x0C, // [1] len=12
            0x02, 0x01, 0x02, // invokeID = 2
            0xA5, 0x07, // [5] Write, len=7
            0x81, 0x00, // success [1] NULL
            0x80, 0x01, 0x03, // failure [0] DataAccessError = 3 (object-access-denied)
            0x81, 0x00, // success [1] NULL
        ];
        let pdu = parse_mms_pdu(data).expect("should parse");
        match &pdu {
            MmsPdu::ConfirmedResponse { write_info, .. } => {
                let wi = write_info.as_ref().expect("write_info should be Some");
                assert_eq!(wi.results.len(), 3);
                // 第 1 个：success
                assert!(wi.results[0].success);
                assert!(wi.results[0].error.is_none());
                // 第 2 个：failure
                assert!(!wi.results[1].success);
                assert_eq!(wi.results[1].error.as_deref(), Some("object-access-denied"));
                // 第 3 个：success
                assert!(wi.results[2].success);
                assert!(wi.results[2].error.is_none());
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    // ====== FileOpen Request 解析测试 ======

    #[test]
    fn test_file_open_request_simple_path() {
        // ConfirmedRequest: FileOpen with fileName="test", initialPosition=0
        //
        // FileOpen content (11 bytes):
        //   fileName [0]: A0 06 (SEQUENCE OF) → 1A 04 "test" (VisibleString)
        //   initialPosition [1]: 81 01 00
        //
        // FileOpen tag: BF 49 (multi-byte tag 73), len=0B(11)
        //   BF 49 0B = 2+1+11 = 14 bytes
        // invokeID: 02 01 05 = 3 bytes
        // Total inner = 3 + 14 = 17 = 0x11
        let data = &[
            0xA0, 0x11, // [0] ConfirmedRequest, len=17
            0x02, 0x01, 0x05, // invokeID = 5
            0xBF, 0x49, 0x0B, // [73] FileOpen, len=11
            0xA0, 0x06, // [0] fileName SEQUENCE OF, len=6
            0x1A, 0x04, 0x74, 0x65, 0x73, 0x74, // VisibleString "test"
            0x81, 0x01, 0x00, // [1] initialPosition = 0
        ];
        let pdu = parse_mms_pdu(data).expect("should parse FileOpen request");
        match &pdu {
            MmsPdu::ConfirmedRequest { invoke_id, service, file_open_info, .. } => {
                assert_eq!(*invoke_id, 5);
                assert_eq!(*service, MmsConfirmedService::FileOpen);
                let fo = file_open_info.as_ref().expect("file_open_info should be Some");
                assert_eq!(fo.file_name, "test");
                assert_eq!(fo.initial_position, 0);
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_file_open_request_with_subdirectory() {
        // FileOpen with 2 path segments: "sub", "a.dat" → "sub/a.dat"
        //
        // fileName [0]: A0 0B → 1A 03 "sub" + 1A 04 "a.dat"(actually 5 bytes)
        //   "sub" = 3 bytes → 1A 03 73 75 62 = 5 bytes
        //   "a.dat" = 5 bytes → 1A 05 61 2E 64 61 74 = 7 bytes
        //   inner = 5 + 7 = 12 → A0 0C
        // initialPosition [1]: 81 01 64 = 3 bytes (value=100)
        // FileOpen content = 14 + 3 = 17 → BF 49 11
        // invokeID = 02 01 0A = 3 bytes
        // Total = 3 + 2 + 1 + 17 = 23 = 0x17
        let data = &[
            0xA0, 0x17, // [0] ConfirmedRequest, len=23
            0x02, 0x01, 0x0A, // invokeID = 10
            0xBF, 0x49, 0x11, // [73] FileOpen, len=17
            0xA0, 0x0C, // [0] fileName SEQUENCE OF, len=12
            0x1A, 0x03, 0x73, 0x75, 0x62, // VisibleString "sub"
            0x1A, 0x05, 0x61, 0x2E, 0x64, 0x61, 0x74, // VisibleString "a.dat"
            0x81, 0x01, 0x64, // [1] initialPosition = 100
        ];
        let pdu = parse_mms_pdu(data).expect("should parse FileOpen with subdirectory");
        match &pdu {
            MmsPdu::ConfirmedRequest { file_open_info, .. } => {
                let fo = file_open_info.as_ref().expect("file_open_info should be Some");
                assert_eq!(fo.file_name, "sub/a.dat");
                assert_eq!(fo.initial_position, 100);
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_file_open_request_no_initial_position() {
        // FileOpen 只有 fileName，缺�� initialPosition → 应默认为 0
        // FileOpen content (8 bytes): A0 06 1A 04 "test"
        // FileOpen TLV: BF 49 08 = 2+1+8 = 11 bytes
        // invokeID: 02 01 01 = 3 bytes
        // Total = 3 + 11 = 14 = 0x0E
        let data = &[
            0xA0, 0x0E, // [0] ConfirmedRequest, len=14
            0x02, 0x01, 0x01, // invokeID = 1
            0xBF, 0x49, 0x08, // [73] FileOpen, len=8
            0xA0, 0x06, // [0] fileName SEQUENCE OF, len=6
            0x1A, 0x04, 0x74, 0x65, 0x73, 0x74, // VisibleString "test"
        ];
        let pdu = parse_mms_pdu(data).expect("should parse");
        match &pdu {
            MmsPdu::ConfirmedRequest { file_open_info, .. } => {
                let fo = file_open_info.as_ref().expect("should have file_open_info");
                assert_eq!(fo.file_name, "test");
                assert_eq!(fo.initial_position, 0, "missing initialPosition should default to 0");
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_file_open_request_empty_filename_segments() {
        // fileName [0] 内没有任何 GraphicString → file_name 为空字符串
        // FileOpen content (5 bytes): A0 00 + 81 01 00
        // FileOpen TLV: BF 49 05 = 2+1+5 = 8 bytes
        // invokeID: 02 01 01 = 3 bytes
        // Total = 3 + 8 = 11 = 0x0B
        let data = &[
            0xA0, 0x0B, // [0] ConfirmedRequest, len=11
            0x02, 0x01, 0x01, // invokeID = 1
            0xBF, 0x49, 0x05, // [73] FileOpen, len=5
            0xA0, 0x00, // [0] fileName SEQUENCE OF, empty
            0x81, 0x01, 0x00, // [1] initialPosition = 0
        ];
        let pdu = parse_mms_pdu(data).expect("should parse");
        match &pdu {
            MmsPdu::ConfirmedRequest { file_open_info, .. } => {
                // 空 fileName 应该仍产生结果，file_name 为空字符串
                let fo = file_open_info.as_ref().expect("should have file_open_info");
                assert!(fo.file_name.is_empty(), "empty segments should produce empty file_name");
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_file_open_request_malformed_no_panic() {
        let cases: Vec<&[u8]> = vec![
            // 空的 FileOpen 内容
            &[0xA0, 0x05, 0x02, 0x01, 0x01, 0xBF, 0x49, 0x00],
            // FileOpen 内容被截断
            &[0xA0, 0x06, 0x02, 0x01, 0x01, 0xBF, 0x49, 0x01, 0xA0],
            // fileName 标签错误（不是 A0）
            &[0xA0, 0x08, 0x02, 0x01, 0x01, 0xBF, 0x49, 0x03, 0x81, 0x01, 0x00],
        ];
        for case in cases {
            let _ = parse_mms_pdu(case);
        }
    }

    // ====== FileOpen Response 解析测试 ======

    #[test]
    fn test_file_open_response_with_attributes() {
        // FileOpen-Response: frsmID=7, sizeOfFile=4096, lastModified="20240101120000Z"
        //
        // frsmID [0]: 80 01 07 = 3 bytes
        // fileAttributes [1]: A1 15 = 2 + 21 = 23 bytes
        //   sizeOfFile [0]: 80 02 10 00 = 4 bytes
        //   lastModified [1]: 81 0F + 15 bytes = 17 bytes
        // FileOpen content = 3 + 23 = 26 bytes
        // FileOpen tag: BF 49 1A = 2 + 1 + 26 = 29 bytes
        // invokeID: 02 01 03 = 3 bytes
        // Total inner = 3 + 29 = 32 = 0x20
        let last_mod = b"20240101120000Z"; // 15 bytes
        let data: Vec<u8> = [
            &[0xA1, 0x20][..],           // [1] ConfirmedResponse, len=32
            &[0x02, 0x01, 0x03],          // invokeID = 3
            &[0xBF, 0x49, 0x1A],          // [73] FileOpen, len=26
            &[0x80, 0x01, 0x07],          // frsmID [0] = 7
            &[0xA1, 0x15],                // fileAttributes [1], len=21
            &[0x80, 0x02, 0x10, 0x00],    // sizeOfFile [0] = 4096
            &[0x81, 0x0F],                // lastModified [1], len=15
            last_mod,
        ].concat();

        let pdu = parse_mms_pdu(&data).expect("should parse FileOpen response");
        match &pdu {
            MmsPdu::ConfirmedResponse { invoke_id, service, file_open_info, .. } => {
                assert_eq!(*invoke_id, 3);
                assert_eq!(*service, MmsConfirmedService::FileOpen);
                let fo = file_open_info.as_ref().expect("file_open_info should be Some");
                assert_eq!(fo.frsm_id, 7);
                assert_eq!(fo.file_size, Some(4096));
                assert_eq!(fo.last_modified.as_deref(), Some("20240101120000Z"));
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    #[test]
    fn test_file_open_response_no_last_modified() {
        // FileOpen-Response: frsmID=1, sizeOfFile=256, 无 lastModified
        //
        // frsmID: 80 01 01 = 3 bytes
        // fileAttributes: A1 04 → sizeOfFile: 80 02 01 00 = 4 bytes
        //   A1 04 = 2 + 4 = 6 bytes
        // FileOpen content = 3 + 6 = 9 → BF 49 09 = 2+1+9 = 12
        // invokeID: 02 01 01 = 3 → total = 3 + 12 = 15 = 0x0F
        let data: Vec<u8> = [
            &[0xA1, 0x0F][..],
            &[0x02, 0x01, 0x01],          // invokeID = 1
            &[0xBF, 0x49, 0x09],          // [73] FileOpen, len=9
            &[0x80, 0x01, 0x01],          // frsmID = 1
            &[0xA1, 0x04],                // fileAttributes, len=4
            &[0x80, 0x02, 0x01, 0x00],    // sizeOfFile = 256
        ].concat();

        let pdu = parse_mms_pdu(&data).expect("should parse");
        match &pdu {
            MmsPdu::ConfirmedResponse { file_open_info, .. } => {
                let fo = file_open_info.as_ref().expect("should have file_open_info");
                assert_eq!(fo.frsm_id, 1);
                assert_eq!(fo.file_size, Some(256));
                assert_eq!(fo.last_modified, None, "missing lastModified should be None");
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    // ====== FileRead 请求/响应解析测试 ======

    #[test]
    fn test_file_read_request_frsm_id() {
        // FileRead-Request ::= Integer32 (just frsmID)
        // tag=74: BF 4A (multi-byte tag for 74)
        // content = just the integer value (frsmID=7)
        //
        // FileRead content: 直接是 integer 内容 → 07 (1 byte)
        // BF 4A 01 07 = 4 bytes? No — BF 4A is tag, 01 is len, 07 is content = 4 bytes total
        // Wait: parse_ber_tlv on BF 4A will return tag_num=74, and content=the inner bytes
        // The service content passed to our parse function is the raw integer bytes
        //
        // invokeID: 02 01 03 = 3 bytes
        // FileRead tag: BF 4A 01 = 2+1+1 = 4 bytes (content is single byte 0x07)
        // Total = 3 + 4 = 7 = 0x07
        let data = &[
            0xA0, 0x07, // [0] ConfirmedRequest, len=7
            0x02, 0x01, 0x03, // invokeID = 3
            0xBF, 0x4A, 0x01, 0x07, // [74] FileRead, len=1, content=7
        ];
        let pdu = parse_mms_pdu(data).expect("should parse FileRead request");
        match &pdu {
            MmsPdu::ConfirmedRequest { invoke_id, service, file_read_info, .. } => {
                assert_eq!(*invoke_id, 3);
                assert_eq!(*service, MmsConfirmedService::FileRead);
                let fr = file_read_info.as_ref().expect("file_read_info should be Some");
                assert_eq!(fr.frsm_id, 7);
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_file_read_response_data_length_and_more_follows() {
        // FileRead-Response: fileData=5 bytes, moreFollows=false
        // fileData [0]: 80 05 + 5 bytes dummy = 7 bytes
        // moreFollows [1]: 81 01 00 (false) = 3 bytes
        // FileRead content = 7 + 3 = 10
        // BF 4A 0A = 2+1+10 = 13 bytes
        // invokeID: 02 01 01 = 3 bytes
        // Total = 3 + 13 = 16 = 0x10
        let data: Vec<u8> = [
            &[0xA1, 0x10][..],            // [1] ConfirmedResponse, len=16
            &[0x02, 0x01, 0x01],          // invokeID = 1
            &[0xBF, 0x4A, 0x0A],          // [74] FileRead, len=10
            &[0x80, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05], // fileData [0], 5 bytes
            &[0x81, 0x01, 0x00],          // moreFollows [1] = false
        ].concat();

        let pdu = parse_mms_pdu(&data).expect("should parse FileRead response");
        match &pdu {
            MmsPdu::ConfirmedResponse { service, file_read_info, .. } => {
                assert_eq!(*service, MmsConfirmedService::FileRead);
                let fr = file_read_info.as_ref().expect("should have file_read_info");
                assert_eq!(fr.data_length, 5);
                assert_eq!(fr.more_follows, false);
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }

    // ====== FileClose 请求/响应解析测试 ======

    #[test]
    fn test_file_close_request_frsm_id() {
        // FileClose-Request ::= Integer32 (frsmID), tag=75
        // BF 4B = multi-byte tag for 75
        // invokeID: 02 01 02 = 3 bytes
        // FileClose: BF 4B 01 05 = 4 bytes (frsmID=5)
        // Total = 3 + 4 = 7 = 0x07
        let data = &[
            0xA0, 0x07, // [0] ConfirmedRequest, len=7
            0x02, 0x01, 0x02, // invokeID = 2
            0xBF, 0x4B, 0x01, 0x05, // [75] FileClose, len=1, content=5
        ];
        let pdu = parse_mms_pdu(data).expect("should parse FileClose request");
        match &pdu {
            MmsPdu::ConfirmedRequest { invoke_id, service, file_read_info, .. } => {
                assert_eq!(*invoke_id, 2);
                assert_eq!(*service, MmsConfirmedService::FileClose);
                let fr = file_read_info.as_ref().expect("file_read_info should be Some");
                assert_eq!(fr.frsm_id, 5);
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_file_close_response_null() {
        // FileClose-Response ::= NULL (tag=75, empty content)
        // BF 4B 00 = tag(2) + len(1) + content(0) = 3 bytes
        // invokeID: 02 01 02 = 3 bytes
        // Total = 3 + 3 = 6 = 0x06
        let data = &[
            0xA1, 0x06, // [1] ConfirmedResponse, len=6
            0x02, 0x01, 0x02, // invokeID = 2
            0xBF, 0x4B, 0x00, // [75] FileClose, len=0 (NULL)
        ];
        let pdu = parse_mms_pdu(data).expect("should parse FileClose response");
        match &pdu {
            MmsPdu::ConfirmedResponse { invoke_id, service, .. } => {
                assert_eq!(*invoke_id, 2);
                assert_eq!(*service, MmsConfirmedService::FileClose);
            }
            _ => panic!("Expected ConfirmedResponse"),
        }
    }
}
