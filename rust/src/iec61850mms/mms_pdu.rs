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

/// MMS confirmed service request types.
#[derive(Debug, Clone, PartialEq)]
pub enum MmsConfirmedService {
    GetNameList,
    Identify,
    Read,
    Write,
    GetVariableAccessAttributes,
    DefineNamedVariableList,
    GetNamedVariableListAttributes,
    DeleteNamedVariableList,
    GetCapabilityList,
    ObtainFile,
    FileOpen,
    FileRead,
    FileClose,
    FileDirectory,
    FileDelete,
    FileRename,
    Unknown(u8),
}

impl MmsConfirmedService {
    /// Parse the confirmed service tag (context-specific tag within Confirmed-RequestPDU).
    pub fn from_request_tag(tag: u8) -> Self {
        // Tags for ConfirmedServiceRequest CHOICE
        match tag {
            1 => MmsConfirmedService::GetNameList,
            2 => MmsConfirmedService::Identify,
            4 => MmsConfirmedService::Read,
            5 => MmsConfirmedService::Write,
            6 => MmsConfirmedService::GetVariableAccessAttributes,
            11 => MmsConfirmedService::DefineNamedVariableList,
            12 => MmsConfirmedService::GetNamedVariableListAttributes,
            13 => MmsConfirmedService::DeleteNamedVariableList,
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
    pub fn from_response_tag(tag: u8) -> Self {
        // Response tags mirror request tags for most services
        Self::from_request_tag(tag)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MmsConfirmedService::GetNameList => "get_name_list",
            MmsConfirmedService::Identify => "identify",
            MmsConfirmedService::Read => "read",
            MmsConfirmedService::Write => "write",
            MmsConfirmedService::GetVariableAccessAttributes => "get_variable_access_attributes",
            MmsConfirmedService::DefineNamedVariableList => "define_named_variable_list",
            MmsConfirmedService::GetNamedVariableListAttributes => {
                "get_named_variable_list_attributes"
            }
            MmsConfirmedService::DeleteNamedVariableList => "delete_named_variable_list",
            MmsConfirmedService::GetCapabilityList => "get_capability_list",
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
    pub fn from_tag(tag: u8) -> Self {
        match tag {
            0 => MmsUnconfirmedService::InformationReport,
            1 => MmsUnconfirmedService::UnsolicitedStatus,
            2 => MmsUnconfirmedService::EventNotification,
            _ => MmsUnconfirmedService::Unknown(tag),
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
    pub variable_specs: Vec<DomainSpecific>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsWriteRequest {
    pub variable_specs: Vec<DomainSpecific>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsGetNameListRequest {
    pub object_class: Option<String>,
    pub domain_id: Option<String>,
}

/// Top-level MMS PDU types.
#[derive(Debug, Clone, PartialEq)]
pub enum MmsPdu {
    InitiateRequest,
    InitiateResponse,
    InitiateError,
    ConfirmedRequest {
        invoke_id: u32,
        service: MmsConfirmedService,
        read_info: Option<MmsReadRequest>,
        write_info: Option<MmsWriteRequest>,
        get_name_list_info: Option<MmsGetNameListRequest>,
    },
    ConfirmedResponse {
        invoke_id: u32,
        service: MmsConfirmedService,
    },
    ConfirmedError {
        invoke_id: u32,
    },
    UnconfirmedPdu {
        service: MmsUnconfirmedService,
    },
    RejectPdu {
        invoke_id: Option<u32>,
    },
    CancelRequest {
        invoke_id: u32,
    },
    CancelResponse {
        invoke_id: u32,
    },
    CancelError,
    ConcludeRequest,
    ConcludeResponse,
    ConcludeError,
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

/// Parse a BER TLV (Tag-Length-Value) header.
/// Returns (tag_byte, is_constructed, tag_number, content, remaining).
fn parse_ber_tlv(input: &[u8]) -> Result<(u8, bool, u8, &[u8], &[u8]), ()> {
    if input.is_empty() {
        return Err(());
    }

    let tag_byte = input[0];
    let _is_constructed = (tag_byte & 0x20) != 0;
    let tag_number = tag_byte & 0x1F;
    let class = (tag_byte >> 6) & 0x03;

    // For context-specific implicit tags, the tag number is in the low 5 bits
    // For tags >= 31, multi-byte tag encoding is used, but MMS doesn't use them
    // at the top level
    let actual_tag = if class == 2 {
        // Context-specific
        tag_number
    } else {
        tag_number
    };

    let (length, header_len) = parse_ber_length(&input[1..])?;
    let total_header = 1 + header_len;

    if input.len() < total_header + length {
        return Err(());
    }

    let content = &input[total_header..total_header + length];
    let remaining = &input[total_header + length..];

    Ok((tag_byte, _is_constructed, actual_tag, content, remaining))
}

/// Parse BER length encoding.
/// Returns (length_value, bytes_consumed).
fn parse_ber_length(input: &[u8]) -> Result<(usize, usize), ()> {
    if input.is_empty() {
        return Err(());
    }

    let first = input[0];
    if first < 0x80 {
        // Short form
        Ok((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite form - not supported for simplicity
        Err(())
    } else {
        // Long form
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || input.len() < 1 + num_bytes {
            return Err(());
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (input[1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

/// Parse a BER INTEGER value.
fn parse_ber_integer(content: &[u8]) -> Result<u32, ()> {
    if content.is_empty() || content.len() > 4 {
        return Err(());
    }
    let mut val: u32 = 0;
    for &b in content {
        val = (val << 8) | (b as u32);
    }
    Ok(val)
}

/// Parse a BER VisibleString/UTF8String value.
fn parse_ber_string(content: &[u8]) -> String {
    String::from_utf8_lossy(content).to_string()
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
                    // Usually [0] INTEGER for basic class
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
pub fn parse_mms_pdu(input: &[u8]) -> Result<MmsPdu, ()> {
    if input.is_empty() {
        return Err(());
    }

    let (tag_byte, _is_constructed, tag_num, content, _remaining) = parse_ber_tlv(input)?;
    let _class = (tag_byte >> 6) & 0x03;

    // MMS PDU is a CHOICE with context-specific tags
    match tag_num {
        0 => {
            // confirmed-RequestPDU [0]
            parse_confirmed_request(content)
        }
        1 => {
            // confirmed-ResponsePDU [1]
            parse_confirmed_response(content)
        }
        2 => {
            // confirmed-ErrorPDU [2]
            let invoke_id = parse_first_integer(content).unwrap_or(0);
            Ok(MmsPdu::ConfirmedError { invoke_id })
        }
        3 => {
            // unconfirmed-PDU [3]
            parse_unconfirmed_pdu(content)
        }
        4 => {
            // rejectPDU [4]
            let invoke_id = parse_first_integer(content).ok();
            Ok(MmsPdu::RejectPdu { invoke_id })
        }
        5 => {
            // cancel-RequestPDU [5] INTEGER
            let invoke_id = parse_ber_integer(content).unwrap_or(0);
            Ok(MmsPdu::CancelRequest { invoke_id })
        }
        6 => {
            // cancel-ResponsePDU [6] INTEGER
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
    // First element: invokeID (INTEGER)
    let (_, _, _, id_content, rest) = parse_ber_tlv(content)?;
    let invoke_id = parse_ber_integer(id_content)?;

    // Second element: confirmedServiceRequest (CHOICE with context tags)
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

    // confirmedServiceResponse
    let (_, _, service_num, _, _) = parse_ber_tlv(rest)?;
    let service = MmsConfirmedService::from_response_tag(service_num);

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
    fn test_parse_ber_length_short() {
        assert_eq!(parse_ber_length(&[0x05]).unwrap(), (5, 1));
        assert_eq!(parse_ber_length(&[0x7F]).unwrap(), (127, 1));
    }

    #[test]
    fn test_parse_ber_length_long() {
        // Two-byte length: 0x81 0x80 = 128
        assert_eq!(parse_ber_length(&[0x81, 0x80]).unwrap(), (128, 2));
        // Three-byte length: 0x82 0x01 0x00 = 256
        assert_eq!(parse_ber_length(&[0x82, 0x01, 0x00]).unwrap(), (256, 3));
    }

    #[test]
    fn test_parse_ber_integer() {
        assert_eq!(parse_ber_integer(&[0x01]).unwrap(), 1);
        assert_eq!(parse_ber_integer(&[0x00, 0xFF]).unwrap(), 255);
        assert_eq!(parse_ber_integer(&[0x01, 0x00]).unwrap(), 256);
    }

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
