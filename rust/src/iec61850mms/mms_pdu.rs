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
            while !pos.is_empty() {
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
            let invoke_id = parse_first_integer(content)?;
            Ok(MmsPdu::ConfirmedError { invoke_id })
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
            let specs = parse_write_request(service_content, depth + 1);
            if !specs.is_empty() {
                write_info = Some(MmsWriteRequest {
                    variable_specs: specs,
                });
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

/// Parse Write request body to extract variable specifications.
fn parse_write_request(content: &[u8], depth: usize) -> Vec<ObjectNameRef> {
    // WriteRequest ::= SEQUENCE {
    //   variableAccessSpecification VariableAccessSpecification,
    //   listOfData [0] IMPLICIT SEQUENCE OF Data
    // }
    if let Ok((_, _, _, inner, _)) = parse_ber_tlv(content) {
        return parse_variable_access_specification(inner, depth + 1);
    }
    Vec::new()
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
            while !pos.is_empty() && results.len() < 64 {
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
                        // success Data — tag byte 到类型名的映射参照 ISO 9506-2 Data CHOICE:
                        //   [1] 0xA1 array, [2] 0xA2 structure (constructed)
                        //   [3] 0x83 boolean, [4] 0x84 bit-string, [5] 0x85 integer
                        //   [6] 0x86 unsigned, [7] 0x87 floating-point
                        //   [9] 0x89 octet-string, [10] 0x8A visible-string
                        //   [12] 0x8C binary-time, [16] 0x90 mms-string, [17] 0x91 utc-time
                        let type_name = data_tag_name(item_tag_num)
                            .map(|s| s.to_string());

                        // array [1] constructed 0xA1, structure [2] constructed 0xA2
                        let value = if item_tag == 0xA1 || item_tag == 0xA2 {
                            // 计算成员数
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
                            parse_ber_integer(item_inner)
                                .map(|v| v.to_string())
                                .ok()
                        } else if item_tag == 0x87 {
                            // [7] floating-point: first byte = exponent width, rest = IEEE float
                            if item_inner.len() == 5 {
                                // single precision (1 exp + 4 IEEE)
                                let bytes = [item_inner[1], item_inner[2], item_inner[3], item_inner[4]];
                                Some(format!("{}", f32::from_be_bytes(bytes)))
                            } else if item_inner.len() == 9 {
                                // double precision (1 exp + 8 IEEE)
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

                        results.push(MmsAccessResult {
                            success: true,
                            data_type: type_name,
                            value,
                        });
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
        });
    }

    let (_, _, service_num, service_content, _) = parse_ber_tlv(rest)?;
    let service = MmsConfirmedService::from_response_tag(service_num);

    let mut get_name_list_info = None;
    let mut get_named_var_list_attr_info = None;
    let mut read_info = None;
    let mut get_var_access_attr_info = None;
    if service == MmsConfirmedService::GetNameList {
        get_name_list_info = Some(parse_get_name_list_response(service_content, depth + 1));
    } else if service == MmsConfirmedService::GetNamedVariableListAttributes {
        get_named_var_list_attr_info = Some(parse_get_named_var_list_attr_response(service_content, depth + 1));
    } else if service == MmsConfirmedService::Read {
        read_info = Some(parse_read_response(service_content, depth + 1));
    } else if service == MmsConfirmedService::GetVariableAccessAttributes {
        get_var_access_attr_info = Some(parse_get_var_access_attr_response(service_content, depth + 1));
    }

    Ok(MmsPdu::ConfirmedResponse {
        invoke_id,
        service,
        get_name_list_info,
        get_named_var_list_attr_info,
        read_info,
        get_var_access_attr_info,
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
}
