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

//! MMS PDU type definitions.
//!
//! Contains all enums and structs used to represent parsed MMS PDU data.

use std::fmt;

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

/// ObjectName 的三种变体，对应 ASN.1 CHOICE。
#[derive(Debug, Clone, PartialEq)]
pub enum ObjectNameRef {
    VmdSpecific(String),                                       // [0] vmd-specific Identifier
    DomainSpecific { domain_id: String, item_id: String },     // [1] domain-specific
    AaSpecific(String),                                        // [2] aa-specific Identifier
}

/// Additional details extracted from certain service requests/responses.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsReadRequest {
    pub variable_specs: Vec<ObjectNameRef>, // Read 请求中引用的变量列表
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsWriteRequest {
    pub variable_specs: Vec<ObjectNameRef>, // Write 请求中引用的变量列表
    pub data: Vec<MmsAccessResult>,         // Write 请求中的数据值列表（浅层解析）
}

/// Write-Response 中单个变量的写入结果。
///
/// Write-Response ::= SEQUENCE OF CHOICE {
///     failure [0] IMPLICIT DataAccessError,
///     success [1] IMPLICIT NULL
/// }
#[derive(Debug, Clone, PartialEq)]
pub struct MmsWriteResult {
    pub success: bool,
    pub error: Option<String>,  // 失败时包含 DataAccessError 名称
}

/// Write-Response 解析结果。
#[derive(Debug, Clone, PartialEq)]
pub struct MmsWriteResponse {
    pub results: Vec<MmsWriteResult>,  // 上限 64 条
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsGetVarAccessAttrRequest {
    pub object_name: Option<ObjectNameRef>, // name [0] ObjectName
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsGetNameListRequest {
    pub object_class: Option<String>,  // 查询的对象类别（如 named_variable、domain 等）
    pub domain_id: Option<String>,     // 限定查询范围的域名称（仅 domainSpecific 时有值）
    pub object_scope: Option<String>,  // 查询范围："vmd_specific" / "domain_specific" / "aa_specific"
    pub continue_after: Option<String>, // 分页续传标识符
}

/// GetNameList 响应数据。
#[derive(Debug, Clone, PartialEq)]
pub struct MmsGetNameListResponse {
    pub identifiers: Vec<String>, // 返回的名称列表（上限 64 条）
    pub more_follows: bool,       // 是否还有后续数据（ASN.1 DEFAULT TRUE）
}

/// GetNamedVariableListAttributes 请求数据。
///
/// GetNamedVariableListAttributes-Request ::= ObjectName
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsGetNamedVarListAttrRequest {
    pub object_name: Option<ObjectNameRef>, // 查询的数据集名称
}

/// FileOpen-Request 解析结果。
///
/// FileOpen-Request ::= SEQUENCE {
///     fileName         [0] IMPLICIT SEQUENCE OF GraphicString,
///     initialPosition  [1] IMPLICIT Unsigned32
/// }
#[derive(Debug, Clone, PartialEq)]
pub struct MmsFileOpenRequest {
    pub file_name: String,          // 文件路径（多段路径用 "/" 拼接）
    pub initial_position: u32,      // 初始读取位置（字节偏移）
}

/// FileOpen-Response 解析结果。
///
/// FileOpen-Response ::= SEQUENCE {
///     frsmID         [0] IMPLICIT Integer32,
///     fileAttributes [1] IMPLICIT FileAttributes
/// }
/// FileAttributes ::= SEQUENCE {
///     sizeOfFile    [0] IMPLICIT Unsigned32,
///     lastModified  [1] IMPLICIT GeneralizedTime OPTIONAL
/// }
#[derive(Debug, Clone, PartialEq)]
pub struct MmsFileOpenResponse {
    pub frsm_id: u32,                   // 文件读取状态机 ID
    pub file_size: Option<u32>,          // 文件大小（字节）
    pub last_modified: Option<String>,   // 最后修改时间（GeneralizedTime 字符串）
}

/// FileRead-Request 解析结果。
/// FileRead-Request ::= Integer32 (frsmID)
#[derive(Debug, Clone, PartialEq)]
pub struct MmsFileReadRequest {
    pub frsm_id: u32,
}

/// FileRead-Response 解析结果。
/// FileRead-Response ::= SEQUENCE {
///     fileData     [0] IMPLICIT OCTET STRING,
///     moreFollows  [1] IMPLICIT BOOLEAN DEFAULT TRUE
/// }
#[derive(Debug, Clone, PartialEq)]
pub struct MmsFileReadResponse {
    pub data_length: u32,       // fileData 的字节长度（不保存实际内容）
    pub more_follows: bool,     // 是否还有后续数据
}

/// GetNamedVariableListAttributes 响应数据。
///
/// GetNamedVariableListAttributes-Response ::= SEQUENCE {
///   mmsDeletable    [0] IMPLICIT BOOLEAN,
///   listOfVariable  [1] IMPLICIT SEQUENCE OF SEQUENCE {
///     variableSpecification  VariableSpecification,
///     alternateAccess        [5] IMPLICIT AlternateAccess OPTIONAL
///   }
/// }
#[derive(Debug, Clone, PartialEq)]
pub struct MmsGetNamedVarListAttrResponse {
    pub mms_deletable: bool,              // 是否可被 MMS 删除
    pub variables: Vec<ObjectNameRef>,     // 数据集中的变量列表（上限 32 条）
}

/// Read Response 中单个 AccessResult 的扁平化表示
#[derive(Debug, Clone, PartialEq)]
pub struct MmsAccessResult {
    pub success: bool,               // true=success, false=failure
    pub data_type: Option<String>,   // 数据类型名（如 "boolean","integer","structure" 等）
    pub value: Option<String>,       // 值的字符串表示（structure/array 不展开，仅标注成员数）
}

/// Read-Response 解析结果
#[derive(Debug, Clone, PartialEq)]
pub struct MmsReadResponse {
    pub results: Vec<MmsAccessResult>,  // 上限 64 条
}

/// GetVariableAccessAttributes-Response 解析结果
#[derive(Debug, Clone, PartialEq)]
pub struct MmsGetVarAccessAttrResponse {
    pub mms_deletable: bool,            // [0] IMPLICIT BOOLEAN
    pub type_description: Option<String>, // 顶层类型名（如 "structure","boolean","integer" 等）
}

/// Initiate-Request/Response 内部协商参数。
///
/// 字段标签对应 ISO 9506-2 ASN.1 定义，参照 libiec61850 mms_client_initiate.c：
///   [0] localDetailCalling/Called — Integer32
///   [1] proposedMaxServOutstandingCalling/negotiated — Integer16
///   [2] proposedMaxServOutstandingCalled/negotiated — Integer16
///   [3] proposedDataStructureNestingLevel/negotiated — Integer8 OPTIONAL
///   [4] initRequestDetail/initResponseDetail — SEQUENCE {
///         [0] proposedVersionNumber/negotiated — Integer16,
///         [1] proposedParameterCBB/negotiated — ParameterSupportOptions,
///         [2] servicesSupportedCalling/Called — ServiceSupportOptions
///       }
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsInitDetail {
    pub local_detail: Option<u32>,                 // [0] 最大 PDU 大小（字节）
    pub max_serv_outstanding_calling: Option<u32>,  // [1] 主叫方最大并发未完成请求数
    pub max_serv_outstanding_called: Option<u32>,   // [2] 被叫方最大并发未完成请求数
    pub data_structure_nesting_level: Option<u32>,  // [3] 数据结构最大嵌套层级
    pub version_number: Option<u32>,                // [4][0] MMS 协议版本号
    pub supported_services: Option<Vec<u8>>,        // [4][2] 服务支持位图（BIT STRING 原始字节）
}

/// 顶层 MMS PDU 类型，对应 ASN.1 CHOICE 标签 [0]-[13]
#[derive(Debug, Clone, PartialEq)]
pub enum MmsPdu {
    InitiateRequest { detail: Option<MmsInitDetail> },  // [8] 初始化请求
    InitiateResponse { detail: Option<MmsInitDetail> }, // [9] 初始化响应
    InitiateError,                            // [10] 初始化错误
    ConfirmedRequest {                        // [0] 确认请求
        invoke_id: u32,
        service: MmsConfirmedService,
        read_info: Option<MmsReadRequest>,
        write_info: Option<MmsWriteRequest>,
        get_name_list_info: Option<MmsGetNameListRequest>,
        get_var_access_attr_info: Option<MmsGetVarAccessAttrRequest>,
        get_named_var_list_attr_info: Option<MmsGetNamedVarListAttrRequest>,
        file_open_info: Option<MmsFileOpenRequest>,
        file_read_info: Option<MmsFileReadRequest>,
    },
    ConfirmedResponse {                       // [1] 确认响应
        invoke_id: u32,
        service: MmsConfirmedService,
        get_name_list_info: Option<MmsGetNameListResponse>,
        get_named_var_list_attr_info: Option<MmsGetNamedVarListAttrResponse>,
        read_info: Option<MmsReadResponse>,
        get_var_access_attr_info: Option<MmsGetVarAccessAttrResponse>,
        write_info: Option<MmsWriteResponse>,
        file_open_info: Option<MmsFileOpenResponse>,
        file_read_info: Option<MmsFileReadResponse>,
    },
    ConfirmedError {                          // [2] 确认错误
        invoke_id: u32,
        error_class: Option<String>,          // 错误类别名（如 "access"、"service" 等）
        error_code: Option<String>,           // 错误码名（如 "object-non-existent"）
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
            MmsPdu::InitiateRequest { .. } => "initiate_request",
            MmsPdu::InitiateResponse { .. } => "initiate_response",
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

    /// 提取 Write 请求中第一个变量的名称。
    /// - DomainSpecific → item_id
    /// - VmdSpecific / AaSpecific → 直接返回变量名
    pub fn first_write_variable(&self) -> Option<&str> {
        if let MmsPdu::ConfirmedRequest { write_info: Some(ref wi), .. } = self {
            wi.variable_specs.first().map(|spec| match spec {
                ObjectNameRef::VmdSpecific(s) => s.as_str(),
                ObjectNameRef::DomainSpecific { item_id, .. } => item_id.as_str(),
                ObjectNameRef::AaSpecific(s) => s.as_str(),
            })
        } else {
            None
        }
    }

    /// 提取 Write 请求中第一个变量的 domain 名称。
    /// 仅 DomainSpecific 有值，VmdSpecific / AaSpecific 返回 None。
    pub fn first_write_domain(&self) -> Option<&str> {
        if let MmsPdu::ConfirmedRequest { write_info: Some(ref wi), .. } = self {
            wi.variable_specs.first().and_then(|spec| match spec {
                ObjectNameRef::DomainSpecific { domain_id, .. } => Some(domain_id.as_str()),
                _ => None,
            })
        } else {
            None
        }
    }

    /// 提取文件服务事务中的主文件路径。
    /// 当前支持 FileOpen；后续 FileDelete/FileRename/ObtainFile 解析完成后自动接入。
    pub fn file_name(&self) -> Option<&str> {
        if let MmsPdu::ConfirmedRequest { file_open_info: Some(ref fo), .. } = self {
            Some(fo.file_name.as_str())
        } else {
            None
        }
    }

    pub fn invoke_id(&self) -> Option<u32> {
        match self {
            MmsPdu::ConfirmedRequest { invoke_id, .. } => Some(*invoke_id),
            MmsPdu::ConfirmedResponse { invoke_id, .. } => Some(*invoke_id),
            MmsPdu::ConfirmedError { invoke_id, .. } => Some(*invoke_id),
            MmsPdu::CancelRequest { invoke_id } => Some(*invoke_id),
            MmsPdu::CancelResponse { invoke_id } => Some(*invoke_id),
            MmsPdu::RejectPdu { invoke_id } => *invoke_id,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====== MmsConfirmedService 标签映射测试 ======

    #[test]
    fn test_from_request_tag_known_services() {
        assert_eq!(MmsConfirmedService::from_request_tag(0), MmsConfirmedService::Status);
        assert_eq!(MmsConfirmedService::from_request_tag(1), MmsConfirmedService::GetNameList);
        assert_eq!(MmsConfirmedService::from_request_tag(2), MmsConfirmedService::Identify);
        assert_eq!(MmsConfirmedService::from_request_tag(3), MmsConfirmedService::Rename);
        assert_eq!(MmsConfirmedService::from_request_tag(4), MmsConfirmedService::Read);
        assert_eq!(MmsConfirmedService::from_request_tag(5), MmsConfirmedService::Write);
        assert_eq!(MmsConfirmedService::from_request_tag(6), MmsConfirmedService::GetVariableAccessAttributes);
        assert_eq!(MmsConfirmedService::from_request_tag(10), MmsConfirmedService::GetCapabilityList);
        assert_eq!(MmsConfirmedService::from_request_tag(11), MmsConfirmedService::DefineNamedVariableList);
        assert_eq!(MmsConfirmedService::from_request_tag(12), MmsConfirmedService::GetNamedVariableListAttributes);
        assert_eq!(MmsConfirmedService::from_request_tag(13), MmsConfirmedService::DeleteNamedVariableList);
        assert_eq!(MmsConfirmedService::from_request_tag(40), MmsConfirmedService::Start);
        assert_eq!(MmsConfirmedService::from_request_tag(41), MmsConfirmedService::Stop);
        assert_eq!(MmsConfirmedService::from_request_tag(44), MmsConfirmedService::Kill);
        assert_eq!(MmsConfirmedService::from_request_tag(72), MmsConfirmedService::ObtainFile);
        assert_eq!(MmsConfirmedService::from_request_tag(73), MmsConfirmedService::FileOpen);
        assert_eq!(MmsConfirmedService::from_request_tag(74), MmsConfirmedService::FileRead);
        assert_eq!(MmsConfirmedService::from_request_tag(75), MmsConfirmedService::FileClose);
        assert_eq!(MmsConfirmedService::from_request_tag(76), MmsConfirmedService::FileRename);
        assert_eq!(MmsConfirmedService::from_request_tag(77), MmsConfirmedService::FileDelete);
        assert_eq!(MmsConfirmedService::from_request_tag(78), MmsConfirmedService::FileDirectory);
    }

    #[test]
    fn test_from_request_tag_unknown() {
        assert_eq!(MmsConfirmedService::from_request_tag(7), MmsConfirmedService::Unknown(7));
        assert_eq!(MmsConfirmedService::from_request_tag(99), MmsConfirmedService::Unknown(99));
        assert_eq!(MmsConfirmedService::from_request_tag(1000), MmsConfirmedService::Unknown(1000));
    }

    #[test]
    fn test_from_response_tag_mirrors_request() {
        // from_response_tag 直接委托给 from_request_tag
        for tag in [0, 1, 4, 5, 12, 78, 99] {
            assert_eq!(
                MmsConfirmedService::from_response_tag(tag),
                MmsConfirmedService::from_request_tag(tag)
            );
        }
    }

    // ====== as_str 测试 ======

    #[test]
    fn test_confirmed_service_as_str() {
        assert_eq!(MmsConfirmedService::Status.as_str(), "status");
        assert_eq!(MmsConfirmedService::Read.as_str(), "read");
        assert_eq!(MmsConfirmedService::Write.as_str(), "write");
        assert_eq!(MmsConfirmedService::GetNameList.as_str(), "get_name_list");
        assert_eq!(MmsConfirmedService::FileDirectory.as_str(), "file_directory");
        assert_eq!(MmsConfirmedService::Unknown(42).as_str(), "unknown");
    }

    #[test]
    fn test_confirmed_service_display() {
        assert_eq!(format!("{}", MmsConfirmedService::Read), "read");
        assert_eq!(format!("{}", MmsConfirmedService::Unknown(0)), "unknown");
    }

    // ====== MmsUnconfirmedService 测试 ======

    #[test]
    fn test_unconfirmed_service_from_tag() {
        assert_eq!(MmsUnconfirmedService::from_tag(0), MmsUnconfirmedService::InformationReport);
        assert_eq!(MmsUnconfirmedService::from_tag(1), MmsUnconfirmedService::UnsolicitedStatus);
        assert_eq!(MmsUnconfirmedService::from_tag(2), MmsUnconfirmedService::EventNotification);
        assert_eq!(MmsUnconfirmedService::from_tag(3), MmsUnconfirmedService::Unknown(3));
        assert_eq!(MmsUnconfirmedService::from_tag(255), MmsUnconfirmedService::Unknown(255));
    }

    #[test]
    fn test_unconfirmed_service_as_str() {
        assert_eq!(MmsUnconfirmedService::InformationReport.as_str(), "information_report");
        assert_eq!(MmsUnconfirmedService::UnsolicitedStatus.as_str(), "unsolicited_status");
        assert_eq!(MmsUnconfirmedService::EventNotification.as_str(), "event_notification");
        assert_eq!(MmsUnconfirmedService::Unknown(0).as_str(), "unknown");
    }

    #[test]
    fn test_unconfirmed_service_display() {
        assert_eq!(format!("{}", MmsUnconfirmedService::InformationReport), "information_report");
    }

    // ====== MmsPdu 方法测试 ======

    #[test]
    fn test_pdu_type_str() {
        assert_eq!(MmsPdu::InitiateRequest { detail: None }.pdu_type_str(), "initiate_request");
        assert_eq!(MmsPdu::InitiateResponse { detail: None }.pdu_type_str(), "initiate_response");
        assert_eq!(MmsPdu::InitiateError.pdu_type_str(), "initiate_error");
        assert_eq!(MmsPdu::ConcludeRequest.pdu_type_str(), "conclude_request");
        assert_eq!(MmsPdu::ConcludeResponse.pdu_type_str(), "conclude_response");
        assert_eq!(MmsPdu::ConcludeError.pdu_type_str(), "conclude_error");
        assert_eq!(MmsPdu::CancelError.pdu_type_str(), "cancel_error");
        assert_eq!(MmsPdu::ConfirmedError { invoke_id: 0, error_class: None, error_code: None  }.pdu_type_str(), "confirmed_error");
        assert_eq!(MmsPdu::RejectPdu { invoke_id: None }.pdu_type_str(), "reject");
        assert_eq!(MmsPdu::CancelRequest { invoke_id: 0 }.pdu_type_str(), "cancel_request");
        assert_eq!(MmsPdu::CancelResponse { invoke_id: 0 }.pdu_type_str(), "cancel_response");
        assert_eq!(
            MmsPdu::UnconfirmedPdu { service: MmsUnconfirmedService::InformationReport }.pdu_type_str(),
            "unconfirmed"
        );
    }

    #[test]
    fn test_service_str() {
        // ConfirmedRequest → Some
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 1,
            service: MmsConfirmedService::Read,
            read_info: None, write_info: None,
            get_name_list_info: None, get_var_access_attr_info: None,
            get_named_var_list_attr_info: None,
            file_open_info: None,
            file_read_info: None,
        };
        assert_eq!(pdu.service_str(), Some("read"));

        // ConfirmedResponse → Some
        let pdu = MmsPdu::ConfirmedResponse {
            invoke_id: 1,
            service: MmsConfirmedService::Write,
            get_name_list_info: None, get_named_var_list_attr_info: None,
            read_info: None, get_var_access_attr_info: None, write_info: None,
            file_open_info: None,
            file_read_info: None,
        };
        assert_eq!(pdu.service_str(), Some("write"));

        // UnconfirmedPdu → Some
        let pdu = MmsPdu::UnconfirmedPdu { service: MmsUnconfirmedService::EventNotification };
        assert_eq!(pdu.service_str(), Some("event_notification"));

        // 其他类型 → None
        assert_eq!(MmsPdu::ConcludeRequest.service_str(), None);
        assert_eq!(MmsPdu::InitiateRequest { detail: None }.service_str(), None);
        assert_eq!(MmsPdu::ConfirmedError { invoke_id: 0, error_class: None, error_code: None }.service_str(), None);
    }

    #[test]
    fn test_invoke_id() {
        // ConfirmedRequest
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 42,
            service: MmsConfirmedService::Read,
            read_info: None, write_info: None,
            get_name_list_info: None, get_var_access_attr_info: None,
            get_named_var_list_attr_info: None,
            file_open_info: None,
            file_read_info: None,
        };
        assert_eq!(pdu.invoke_id(), Some(42));

        // ConfirmedResponse
        let pdu = MmsPdu::ConfirmedResponse {
            invoke_id: 7,
            service: MmsConfirmedService::Status,
            get_name_list_info: None, get_named_var_list_attr_info: None,
            read_info: None, get_var_access_attr_info: None, write_info: None,
            file_open_info: None,
            file_read_info: None,
        };
        assert_eq!(pdu.invoke_id(), Some(7));

        // ConfirmedError
        assert_eq!(MmsPdu::ConfirmedError { invoke_id: 3, error_class: None, error_code: None }.invoke_id(), Some(3));

        // CancelRequest / CancelResponse
        assert_eq!(MmsPdu::CancelRequest { invoke_id: 10 }.invoke_id(), Some(10));
        assert_eq!(MmsPdu::CancelResponse { invoke_id: 11 }.invoke_id(), Some(11));

        // RejectPdu with invoke_id
        assert_eq!(MmsPdu::RejectPdu { invoke_id: Some(5) }.invoke_id(), Some(5));
        // RejectPdu without invoke_id
        assert_eq!(MmsPdu::RejectPdu { invoke_id: None }.invoke_id(), None);

        // 无 invoke_id 的 PDU 类型
        assert_eq!(MmsPdu::ConcludeRequest.invoke_id(), None);
        assert_eq!(MmsPdu::ConcludeResponse.invoke_id(), None);
        assert_eq!(MmsPdu::InitiateRequest { detail: None }.invoke_id(), None);
        assert_eq!(MmsPdu::CancelError.invoke_id(), None);
    }

    // ====== first_write_variable / first_write_domain 测试 ======

    /// 构造一个 Write 请求 PDU 的辅助函数
    fn make_write_request_pdu(specs: Vec<ObjectNameRef>) -> MmsPdu {
        MmsPdu::ConfirmedRequest {
            invoke_id: 1,
            service: MmsConfirmedService::Write,
            read_info: None,
            write_info: Some(MmsWriteRequest {
                variable_specs: specs,
                data: vec![],
            }),
            get_name_list_info: None,
            get_var_access_attr_info: None,
            get_named_var_list_attr_info: None,
            file_open_info: None,
            file_read_info: None,
        }
    }

    #[test]
    fn test_write_variable_from_domain_specific() {
        let pdu = make_write_request_pdu(vec![
            ObjectNameRef::DomainSpecific {
                domain_id: "TestDomain".to_string(),
                item_id: "GGIO1$ST$Ind1$stVal".to_string(),
            },
        ]);
        assert_eq!(pdu.first_write_variable(), Some("GGIO1$ST$Ind1$stVal"));
    }

    #[test]
    fn test_write_domain_from_domain_specific() {
        let pdu = make_write_request_pdu(vec![
            ObjectNameRef::DomainSpecific {
                domain_id: "TestDomain".to_string(),
                item_id: "GGIO1$ST$Ind1$stVal".to_string(),
            },
        ]);
        assert_eq!(pdu.first_write_domain(), Some("TestDomain"));
    }

    #[test]
    fn test_write_domain_none_for_vmd_specific() {
        let pdu = make_write_request_pdu(vec![
            ObjectNameRef::VmdSpecific("VmdVar1".to_string()),
        ]);
        // VmdSpecific 没有 domain，应返回 None
        assert_eq!(pdu.first_write_domain(), None);
        // 但 variable 名应正常返回
        assert_eq!(pdu.first_write_variable(), Some("VmdVar1"));
    }

    #[test]
    fn test_write_variable_none_for_non_write_pdu() {
        // Read 请求不应返回 write variable
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 1,
            service: MmsConfirmedService::Read,
            read_info: None,
            write_info: None,
            get_name_list_info: None,
            get_var_access_attr_info: None,
            get_named_var_list_attr_info: None,
            file_open_info: None,
            file_read_info: None,
        };
        assert_eq!(pdu.first_write_variable(), None);
        assert_eq!(pdu.first_write_domain(), None);
    }

    #[test]
    fn test_write_variable_empty_specs() {
        // Write 请求但 variable_specs 为空
        let pdu = make_write_request_pdu(vec![]);
        assert_eq!(pdu.first_write_variable(), None);
        assert_eq!(pdu.first_write_domain(), None);
    }

    // ====== multi-buffer 索引提取测试（模拟 detect.rs 中 local_id 迭代） ======

    /// 从 Write 请求 PDU 中提取 variable_specs，模拟 detect.rs 的 get 回调逻辑
    fn get_write_variable_specs(pdu: &MmsPdu) -> Option<&Vec<ObjectNameRef>> {
        if let MmsPdu::ConfirmedRequest { write_info: Some(ref wi), .. } = pdu {
            Some(&wi.variable_specs)
        } else {
            None
        }
    }

    #[test]
    fn test_multi_buffer_write_variable_3_items() {
        // 3 个变量的 Write 请求，模拟 local_id=0,1,2 分别返回对应变量名
        let pdu = make_write_request_pdu(vec![
            ObjectNameRef::DomainSpecific {
                domain_id: "Domain1".to_string(),
                item_id: "Var1$ST$stVal".to_string(),
            },
            ObjectNameRef::DomainSpecific {
                domain_id: "Domain2".to_string(),
                item_id: "Var2$CO$ctlVal".to_string(),
            },
            ObjectNameRef::VmdSpecific("VmdVar3".to_string()),
        ]);

        let specs = get_write_variable_specs(&pdu).unwrap();
        assert_eq!(specs.len(), 3);

        // local_id=0
        match &specs[0] {
            ObjectNameRef::DomainSpecific { item_id, .. } => assert_eq!(item_id, "Var1$ST$stVal"),
            _ => panic!("expected DomainSpecific"),
        }
        // local_id=1
        match &specs[1] {
            ObjectNameRef::DomainSpecific { item_id, .. } => assert_eq!(item_id, "Var2$CO$ctlVal"),
            _ => panic!("expected DomainSpecific"),
        }
        // local_id=2
        match &specs[2] {
            ObjectNameRef::VmdSpecific(s) => assert_eq!(s, "VmdVar3"),
            _ => panic!("expected VmdSpecific"),
        }
        // local_id=3 → 越界
        assert!(specs.get(3).is_none());
    }

    #[test]
    fn test_multi_buffer_write_domain_mixed_specs() {
        // 混合 vmd_specific 和 domain_specific，验证 domain 提取逻辑
        let pdu = make_write_request_pdu(vec![
            ObjectNameRef::VmdSpecific("VmdVar".to_string()),
            ObjectNameRef::DomainSpecific {
                domain_id: "MyDomain".to_string(),
                item_id: "Item1".to_string(),
            },
            ObjectNameRef::AaSpecific("AaVar".to_string()),
        ]);

        let specs = get_write_variable_specs(&pdu).unwrap();

        // local_id=0: VmdSpecific → 无 domain
        assert!(!matches!(&specs[0], ObjectNameRef::DomainSpecific { .. }));

        // local_id=1: DomainSpecific → 有 domain
        match &specs[1] {
            ObjectNameRef::DomainSpecific { domain_id, .. } => assert_eq!(domain_id, "MyDomain"),
            _ => panic!("expected DomainSpecific at index 1"),
        }

        // local_id=2: AaSpecific → 无 domain
        assert!(!matches!(&specs[2], ObjectNameRef::DomainSpecific { .. }));
    }

    #[test]
    fn test_multi_buffer_empty_specs_no_panic() {
        let pdu = make_write_request_pdu(vec![]);
        let specs = get_write_variable_specs(&pdu).unwrap();
        assert!(specs.is_empty());
        assert!(specs.get(0).is_none());
    }

    // ====== file_name() 方法测试 ======

    #[test]
    fn test_file_name_from_file_open_request() {
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 1,
            service: MmsConfirmedService::FileOpen,
            read_info: None,
            write_info: None,
            get_name_list_info: None,
            get_var_access_attr_info: None,
            get_named_var_list_attr_info: None,
            file_open_info: Some(MmsFileOpenRequest {
                file_name: "firmware.bin".to_string(),
                initial_position: 0,
            }),
            file_read_info: None,
        };
        assert_eq!(pdu.file_name(), Some("firmware.bin"));
    }

    #[test]
    fn test_file_name_none_for_read_request() {
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 1,
            service: MmsConfirmedService::Read,
            read_info: None,
            write_info: None,
            get_name_list_info: None,
            get_var_access_attr_info: None,
            get_named_var_list_attr_info: None,
            file_open_info: None,
            file_read_info: None,
        };
        assert_eq!(pdu.file_name(), None);
    }

    #[test]
    fn test_file_name_none_for_write_request() {
        let pdu = make_write_request_pdu(vec![
            ObjectNameRef::DomainSpecific {
                domain_id: "D".to_string(),
                item_id: "Var".to_string(),
            },
        ]);
        assert_eq!(pdu.file_name(), None);
    }
}
