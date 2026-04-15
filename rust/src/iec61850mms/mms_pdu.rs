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

use std::fmt;

use super::ber::{parse_ber_integer, parse_ber_string, parse_ber_tlv};

/// MMS confirmed service request types.
#[derive(Debug, Clone, PartialEq)]
pub enum MmsConfirmedService {
    Status,
    GetNameList,
    Identify,
    Rename,
    Read,
    Write,
    GetVariableAccessAttributes,
    GetCapabilityList,
    DefineNamedVariableList,
    GetNamedVariableListAttributes,
    DeleteNamedVariableList,
    TakeControl,
    RelinquishControl,
    InitiateDownloadSequence,
    DownloadSegment,
    TerminateDownloadSequence,
    InitiateUploadSequence,
    UploadSegment,
    TerminateUploadSequence,
    RequestDomainDownload,
    RequestDomainUpload,
    LoadDomainContent,
    StoreDomainContent,
    DeleteDomain,
    GetDomainAttributes,
    CreateProgramInvocation,
    DeleteProgramInvocation,
    Start,
    Stop,
    Resume,
    Reset,
    Kill,
    GetProgramInvocationAttributes,
    GetAlarmSummary,
    ObtainFile,
    FileOpen,
    FileRead,
    FileClose,
    FileRename,
    FileDelete,
    FileDirectory,
    Unknown(u32),
}

impl MmsConfirmedService {
    /// 根据 ConfirmedServiceRequest CHOICE 的上下文标签号解析服务类型。
    /// 标签号对应 ISO 9506-2 ASN.1 定义中的 CHOICE 编号。
    pub fn from_request_tag(tag: u32) -> Self {
        // ConfirmedServiceRequest CHOICE 标签 → 服务类型
        match tag {
            0 => MmsConfirmedService::Status,
            1 => MmsConfirmedService::GetNameList,
            2 => MmsConfirmedService::Identify,
            3 => MmsConfirmedService::Rename,
            4 => MmsConfirmedService::Read,
            5 => MmsConfirmedService::Write,
            6 => MmsConfirmedService::GetVariableAccessAttributes,
            10 => MmsConfirmedService::GetCapabilityList,
            11 => MmsConfirmedService::DefineNamedVariableList,
            12 => MmsConfirmedService::GetNamedVariableListAttributes,
            13 => MmsConfirmedService::DeleteNamedVariableList,
            19 => MmsConfirmedService::TakeControl,
            20 => MmsConfirmedService::RelinquishControl,
            26 => MmsConfirmedService::InitiateDownloadSequence,
            27 => MmsConfirmedService::DownloadSegment,
            28 => MmsConfirmedService::TerminateDownloadSequence,
            29 => MmsConfirmedService::InitiateUploadSequence,
            30 => MmsConfirmedService::UploadSegment,
            31 => MmsConfirmedService::TerminateUploadSequence,
            32 => MmsConfirmedService::RequestDomainDownload,
            33 => MmsConfirmedService::RequestDomainUpload,
            34 => MmsConfirmedService::LoadDomainContent,
            35 => MmsConfirmedService::StoreDomainContent,
            36 => MmsConfirmedService::DeleteDomain,
            37 => MmsConfirmedService::GetDomainAttributes,
            38 => MmsConfirmedService::CreateProgramInvocation,
            39 => MmsConfirmedService::DeleteProgramInvocation,
            40 => MmsConfirmedService::Start,
            41 => MmsConfirmedService::Stop,
            42 => MmsConfirmedService::Resume,
            43 => MmsConfirmedService::Reset,
            44 => MmsConfirmedService::Kill,
            45 => MmsConfirmedService::GetProgramInvocationAttributes,
            63 => MmsConfirmedService::GetAlarmSummary,
            72 => MmsConfirmedService::ObtainFile,
            73 => MmsConfirmedService::FileOpen,
            74 => MmsConfirmedService::FileRead,
            75 => MmsConfirmedService::FileClose,
            76 => MmsConfirmedService::FileRename,
            77 => MmsConfirmedService::FileDelete,
            78 => MmsConfirmedService::FileDirectory,
            _ => MmsConfirmedService::Unknown(tag),
        }
    }

    /// Parse the confirmed service tag from a response.
    pub fn from_response_tag(tag: u32) -> Self {
        // Response tags mirror request tags for most services
        Self::from_request_tag(tag)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MmsConfirmedService::Status => "status",
            MmsConfirmedService::GetNameList => "get_name_list",
            MmsConfirmedService::Identify => "identify",
            MmsConfirmedService::Rename => "rename",
            MmsConfirmedService::Read => "read",
            MmsConfirmedService::Write => "write",
            MmsConfirmedService::GetVariableAccessAttributes => "get_variable_access_attributes",
            MmsConfirmedService::GetCapabilityList => "get_capability_list",
            MmsConfirmedService::DefineNamedVariableList => "define_named_variable_list",
            MmsConfirmedService::GetNamedVariableListAttributes => {
                "get_named_variable_list_attributes"
            }
            MmsConfirmedService::DeleteNamedVariableList => "delete_named_variable_list",
            MmsConfirmedService::TakeControl => "take_control",
            MmsConfirmedService::RelinquishControl => "relinquish_control",
            MmsConfirmedService::InitiateDownloadSequence => "initiate_download_sequence",
            MmsConfirmedService::DownloadSegment => "download_segment",
            MmsConfirmedService::TerminateDownloadSequence => "terminate_download_sequence",
            MmsConfirmedService::InitiateUploadSequence => "initiate_upload_sequence",
            MmsConfirmedService::UploadSegment => "upload_segment",
            MmsConfirmedService::TerminateUploadSequence => "terminate_upload_sequence",
            MmsConfirmedService::RequestDomainDownload => "request_domain_download",
            MmsConfirmedService::RequestDomainUpload => "request_domain_upload",
            MmsConfirmedService::LoadDomainContent => "load_domain_content",
            MmsConfirmedService::StoreDomainContent => "store_domain_content",
            MmsConfirmedService::DeleteDomain => "delete_domain",
            MmsConfirmedService::GetDomainAttributes => "get_domain_attributes",
            MmsConfirmedService::CreateProgramInvocation => "create_program_invocation",
            MmsConfirmedService::DeleteProgramInvocation => "delete_program_invocation",
            MmsConfirmedService::Start => "start",
            MmsConfirmedService::Stop => "stop",
            MmsConfirmedService::Resume => "resume",
            MmsConfirmedService::Reset => "reset",
            MmsConfirmedService::Kill => "kill",
            MmsConfirmedService::GetProgramInvocationAttributes => {
                "get_program_invocation_attributes"
            }
            MmsConfirmedService::GetAlarmSummary => "get_alarm_summary",
            MmsConfirmedService::ObtainFile => "obtain_file",
            MmsConfirmedService::FileOpen => "file_open",
            MmsConfirmedService::FileRead => "file_read",
            MmsConfirmedService::FileClose => "file_close",
            MmsConfirmedService::FileDirectory => "file_directory",
            MmsConfirmedService::FileDelete => "file_delete",
            MmsConfirmedService::FileRename => "file_rename",
            MmsConfirmedService::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for MmsConfirmedService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// MMS unconfirmed service types.
#[derive(Debug, Clone, PartialEq)]
pub enum MmsUnconfirmedService {
    InformationReport,
    UnsolicitedStatus,
    EventNotification,
    Unknown(u8),
}

impl MmsUnconfirmedService {
    /// UnconfirmedService CHOICE 标签 → 服务类型
    pub fn from_tag(tag: u32) -> Self {
        match tag {
            0 => MmsUnconfirmedService::InformationReport, // [0] 信息报告
            1 => MmsUnconfirmedService::UnsolicitedStatus,  // [1] 主动状态上报
            2 => MmsUnconfirmedService::EventNotification,  // [2] 事件通知
            _ => MmsUnconfirmedService::Unknown(tag as u8),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MmsUnconfirmedService::InformationReport => "information_report",
            MmsUnconfirmedService::UnsolicitedStatus => "unsolicited_status",
            MmsUnconfirmedService::EventNotification => "event_notification",
            MmsUnconfirmedService::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for MmsUnconfirmedService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Domain-specific object name reference.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DomainSpecific {
    pub domain_id: String,
    pub item_id: String,
}

/// Variable specification from Read/Write requests.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum VariableSpecification {
    Named(DomainSpecific),
    Address(u32),
    Other,
}

/// Additional details extracted from certain service requests/responses.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsReadRequest {
    pub variable_specs: Vec<DomainSpecific>, // Read 请求中引用的变量列表（domain.item）
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsWriteRequest {
    pub variable_specs: Vec<DomainSpecific>, // Write 请求中引用的变量列表
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsGetNameListRequest {
    pub object_class: Option<String>, // 查询的对象类别（如 named_variable、domain 等）
    pub domain_id: Option<String>,    // 限定查询范围的域名称
}

/// 顶层 MMS PDU 类型，对应 ASN.1 CHOICE 标签 [0]-[13]
#[derive(Debug, Clone, PartialEq)]
pub enum MmsPdu {
    InitiateRequest,                          // [8] 初始化请求
    InitiateResponse,                         // [9] 初始化响应
    InitiateError,                            // [10] 初始化错误
    ConfirmedRequest {                        // [0] 确认请求
        invoke_id: u32,
        service: MmsConfirmedService,
        read_info: Option<MmsReadRequest>,
        write_info: Option<MmsWriteRequest>,
        get_name_list_info: Option<MmsGetNameListRequest>,
    },
    ConfirmedResponse {                       // [1] 确认响应
        invoke_id: u32,
        service: MmsConfirmedService,
    },
    ConfirmedError {                          // [2] 确认错误
        invoke_id: u32,
    },
    UnconfirmedPdu {                          // [3] 未确认 PDU
        service: MmsUnconfirmedService,
    },
    RejectPdu {                               // [4] 拒绝 PDU
        invoke_id: Option<u32>,
    },
    CancelRequest {                           // [5] 取消请求
        invoke_id: u32,
    },
    CancelResponse {                          // [6] 取消响应
        invoke_id: u32,
    },
    CancelError,                              // [7] 取消错误
    ConcludeRequest,                          // [11] 结束请求
    ConcludeResponse,                         // [12] 结束响应
    ConcludeError,                            // [13] 结束错误
}

impl MmsPdu {
    pub fn pdu_type_str(&self) -> &'static str {
        match self {
            MmsPdu::InitiateRequest => "initiate_request",
            MmsPdu::InitiateResponse => "initiate_response",
            MmsPdu::InitiateError => "initiate_error",
            MmsPdu::ConfirmedRequest { .. } => "confirmed_request",
            MmsPdu::ConfirmedResponse { .. } => "confirmed_response",
            MmsPdu::ConfirmedError { .. } => "confirmed_error",
            MmsPdu::UnconfirmedPdu { .. } => "unconfirmed",
            MmsPdu::RejectPdu { .. } => "reject",
            MmsPdu::CancelRequest { .. } => "cancel_request",
            MmsPdu::CancelResponse { .. } => "cancel_response",
            MmsPdu::CancelError => "cancel_error",
            MmsPdu::ConcludeRequest => "conclude_request",
            MmsPdu::ConcludeResponse => "conclude_response",
            MmsPdu::ConcludeError => "conclude_error",
        }
    }

    pub fn service_str(&self) -> Option<&str> {
        match self {
            MmsPdu::ConfirmedRequest { service, .. } => Some(service.as_str()),
            MmsPdu::ConfirmedResponse { service, .. } => Some(service.as_str()),
            MmsPdu::UnconfirmedPdu { service } => Some(service.as_str()),
            _ => None,
        }
    }

    pub fn invoke_id(&self) -> Option<u32> {
        match self {
            MmsPdu::ConfirmedRequest { invoke_id, .. } => Some(*invoke_id),
            MmsPdu::ConfirmedResponse { invoke_id, .. } => Some(*invoke_id),
            MmsPdu::ConfirmedError { invoke_id } => Some(*invoke_id),
            MmsPdu::CancelRequest { invoke_id } => Some(*invoke_id),
            MmsPdu::CancelResponse { invoke_id } => Some(*invoke_id),
            MmsPdu::RejectPdu { invoke_id } => *invoke_id,
            _ => None,
        }
    }
}

/// Extract domain-specific object references from a Read/Write request.
/// The variable access specification in MMS uses nested constructed tags.
fn parse_variable_access_specification(content: &[u8]) -> Vec<DomainSpecific> {
    let mut specs = Vec::new();

    // VariableAccessSpecification ::= CHOICE {
    //   listOfVariable [0] IMPLICIT SEQUENCE OF ...
    //   variableListName [1] ObjectName
    // }
    if let Ok((tag_byte, _, _, inner, _)) = parse_ber_tlv(content) {
        if tag_byte == 0xA0 {
            // listOfVariable: SEQUENCE OF (SEQUENCE { variableSpecification, ... })
            let mut pos = inner;
            while !pos.is_empty() {
                if let Ok((_, _, _, seq_content, rem)) = parse_ber_tlv(pos) {
                    if let Some(ds) = extract_domain_specific_from_var_spec(seq_content) {
                        specs.push(ds);
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

/// Extract a DomainSpecific reference from a VariableSpecification element.
fn extract_domain_specific_from_var_spec(content: &[u8]) -> Option<DomainSpecific> {
    // VariableSpecification ::= CHOICE {
    //   name [0] ObjectName,
    //   address [1] Address,
    //   ...
    // }
    if let Ok((tag_byte, _, _, name_content, _)) = parse_ber_tlv(content) {
        if tag_byte == 0xA0 {
            // ObjectName ::= CHOICE {
            //   vmd-specific [0] IMPLICIT Identifier,
            //   domain-specific [1] IMPLICIT SEQUENCE { domainId, itemId },
            //   aa-specific [2] IMPLICIT Identifier,
            // }
            return parse_object_name(name_content);
        }
    }
    None
}

/// Parse an ObjectName and extract domain-specific reference if present.
fn parse_object_name(content: &[u8]) -> Option<DomainSpecific> {
    if let Ok((tag_byte, _, _, inner, _)) = parse_ber_tlv(content) {
        if tag_byte == 0xA1 {
            // domain-specific: SEQUENCE { domainId Identifier, itemId Identifier }
            return parse_domain_specific_sequence(inner);
        }
    }
    None
}

/// Parse a domain-specific SEQUENCE { domainId, itemId }.
fn parse_domain_specific_sequence(content: &[u8]) -> Option<DomainSpecific> {
    // First element: domainId (VisibleString)
    let (_, _, _, domain_bytes, rem) = parse_ber_tlv(content).ok()?;
    let domain_id = parse_ber_string(domain_bytes);

    // Second element: itemId (VisibleString)
    let (_, _, _, item_bytes, _) = parse_ber_tlv(rem).ok()?;
    let item_id = parse_ber_string(item_bytes);

    Some(DomainSpecific { domain_id, item_id })
}

/// Parse a GetNameList request to extract object class and domain.
fn parse_get_name_list_request(content: &[u8]) -> MmsGetNameListRequest {
    let mut result = MmsGetNameListRequest::default();
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
                    // objectScope: CHOICE
                    // [0] vmdSpecific NULL
                    // [1] domainSpecific Identifier
                    // [2] aaSpecific NULL
                    if let Ok((scope_tag, _, _, scope_content, _)) = parse_ber_tlv(inner) {
                        if scope_tag == 0x81 {
                            result.domain_id = Some(parse_ber_string(scope_content));
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

    result
}

/// Parse a top-level MMS PDU from BER-encoded data.
pub(super) fn parse_mms_pdu(input: &[u8]) -> Result<MmsPdu, ()> {
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
            parse_confirmed_request(content)
        }
        1 => {
            //解析ConfirmedResponse确认响应
            parse_confirmed_response(content)
        }
        2 => {
            //解析ConfirmedError确认错误
            let invoke_id = parse_first_integer(content).unwrap_or(0);
            Ok(MmsPdu::ConfirmedError { invoke_id })
        }
        3 => {
            //解析UnconfirmedPdu未确认 PDU
            parse_unconfirmed_pdu(content)
        }
        4 => {
            //解析RejectPdu拒绝 PDU
            let invoke_id = parse_first_integer(content).ok();
            Ok(MmsPdu::RejectPdu { invoke_id })
        }
        5 => {
            //解析CancelRequest取消请求
            let invoke_id = parse_ber_integer(content).unwrap_or(0);
            Ok(MmsPdu::CancelRequest { invoke_id })
        }
        6 => {
            //解析CancelResponse取消响应
            let invoke_id = parse_ber_integer(content).unwrap_or(0);
            Ok(MmsPdu::CancelResponse { invoke_id })
        }
        7 => Ok(MmsPdu::CancelError),
        8 => Ok(MmsPdu::InitiateRequest),
        9 => Ok(MmsPdu::InitiateResponse),
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
fn parse_confirmed_request(content: &[u8]) -> Result<MmsPdu, ()> {
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

    match service {
        MmsConfirmedService::Read => {
            let specs = parse_read_request(service_content);
            if !specs.is_empty() {
                read_info = Some(MmsReadRequest {
                    variable_specs: specs,
                });
            }
        }
        MmsConfirmedService::Write => {
            let specs = parse_write_request(service_content);
            if !specs.is_empty() {
                write_info = Some(MmsWriteRequest {
                    variable_specs: specs,
                });
            }
        }
        MmsConfirmedService::GetNameList => {
            get_name_list_info = Some(parse_get_name_list_request(service_content));
        }
        _ => {}
    }

    Ok(MmsPdu::ConfirmedRequest {
        invoke_id,
        service,
        read_info,
        write_info,
        get_name_list_info,
    })
}

/// Parse Read request body to extract variable specifications.
fn parse_read_request(content: &[u8]) -> Vec<DomainSpecific> {
    // ReadRequest ::= SEQUENCE {
    //   specificationWithResult [0] IMPLICIT BOOLEAN DEFAULT FALSE,
    //   variableAccessSpecification [1] VariableAccessSpecification
    // }
    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            if tag_byte == 0xA1 {
                return parse_variable_access_specification(inner);
            }
            pos = rem;
        } else {
            break;
        }
    }
    Vec::new()
}

/// Parse Write request body to extract variable specifications.
fn parse_write_request(content: &[u8]) -> Vec<DomainSpecific> {
    // WriteRequest ::= SEQUENCE {
    //   variableAccessSpecification VariableAccessSpecification,
    //   listOfData [0] IMPLICIT SEQUENCE OF Data
    // }
    if let Ok((_, _, _, inner, _)) = parse_ber_tlv(content) {
        return parse_variable_access_specification(inner);
    }
    Vec::new()
}

/// Parse a Confirmed-ResponsePDU.
fn parse_confirmed_response(content: &[u8]) -> Result<MmsPdu, ()> {
    // invokeID
    let (_, _, _, id_content, rest) = parse_ber_tlv(content)?;
    let invoke_id = parse_ber_integer(id_content)?;

    // confirmedServiceResponse - may be absent in minimal responses
    let service = if rest.is_empty() {
        MmsConfirmedService::Unknown(0)
    } else {
        let (_, _, service_num, _, _) = parse_ber_tlv(rest)?;
        MmsConfirmedService::from_response_tag(service_num)
    };

    Ok(MmsPdu::ConfirmedResponse { invoke_id, service })
}

/// Parse an Unconfirmed-PDU.
fn parse_unconfirmed_pdu(content: &[u8]) -> Result<MmsPdu, ()> {
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
        assert_eq!(result.unwrap(), MmsPdu::InitiateRequest);
    }

    #[test]
    fn test_parse_initiate_response() {
        let data = &[0xA9, 0x03, 0x80, 0x01, 0x01];
        let result = parse_mms_pdu(data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MmsPdu::InitiateResponse);
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
                assert_eq!(ri.variable_specs[0].domain_id, "LLN0");
                assert_eq!(ri.variable_specs[0].item_id, "Mod");
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
            MmsPdu::ConfirmedResponse { invoke_id, service } => {
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
}
