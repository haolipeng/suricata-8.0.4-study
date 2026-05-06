//! Confirmed Request/Response framework parsing.

use super::error::{MmsParseError, MmsParseResult};
use crate::iec61850mms::ber::{parse_ber_integer, parse_ber_tlv, MAX_BER_DEPTH};
use crate::iec61850mms::mms_types::*;

/// Parse a Confirmed-RequestPDU.
///
/// Confirmed-RequestPDU ::= SEQUENCE {
///   invokeID  Unsigned32,
///   confirmedServiceRequest  ConfirmedServiceRequest
/// }
pub(super) fn parse_confirmed_request(content: &[u8], depth: usize) -> MmsParseResult<MmsPdu> {
    if depth > MAX_BER_DEPTH {
        return Err(MmsParseError::depth_limit());
    }
    // 第一个元素：invokeID（INTEGER），用于请求/响应配对
    let (_, _, _, id_content, rest) = parse_ber_tlv(content)
        .map_err(|_| MmsParseError::malformed("missing confirmed request invoke-id"))?;
    let invoke_id = parse_ber_integer(id_content)
        .map_err(|_| MmsParseError::malformed("invalid confirmed request invoke-id"))?;

    // 第二个元素：confirmedServiceRequest（CHOICE），按上下文标签分发到具体服务
    let (service_tag, _, service_num, service_content, _) = parse_ber_tlv(rest)
        .map_err(|_| MmsParseError::malformed("missing confirmed request service"))?;
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
            let specs = super::read_write::parse_read_request(service_content, depth + 1);
            if !specs.is_empty() {
                read_info = Some(MmsReadRequest {
                    variable_specs: specs,
                });
            }
        }
        MmsConfirmedService::Write => {
            let wi = super::read_write::parse_write_request(service_content, depth + 1);
            if !wi.variable_specs.is_empty() || !wi.data.is_empty() {
                write_info = Some(wi);
            }
        }
        MmsConfirmedService::GetNameList => {
            get_name_list_info = Some(super::name_services::parse_get_name_list_request(
                service_content,
                depth + 1,
            ));
        }
        MmsConfirmedService::GetVariableAccessAttributes => {
            get_var_access_attr_info = Some(
                super::name_services::parse_get_var_access_attr_request(service_content, depth + 1),
            );
        }
        MmsConfirmedService::GetNamedVariableListAttributes => {
            get_named_var_list_attr_info =
                Some(super::name_services::parse_get_named_var_list_attr_request(
                    service_content,
                    depth + 1,
                ));
        }
        MmsConfirmedService::FileOpen => {
            file_open_info =
                super::file_services::parse_file_open_request(service_content, depth + 1);
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

/// Parse a Confirmed-ResponsePDU.
pub(super) fn parse_confirmed_response(content: &[u8], depth: usize) -> MmsParseResult<MmsPdu> {
    if depth > MAX_BER_DEPTH {
        return Err(MmsParseError::depth_limit());
    }
    // invokeID
    let (_, _, _, id_content, rest) = parse_ber_tlv(content)
        .map_err(|_| MmsParseError::malformed("missing confirmed response invoke-id"))?;
    let invoke_id = parse_ber_integer(id_content)
        .map_err(|_| MmsParseError::malformed("invalid confirmed response invoke-id"))?;

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

    let (_, _, service_num, service_content, _) = parse_ber_tlv(rest)
        .map_err(|_| MmsParseError::malformed("invalid confirmed response service"))?;
    let service = MmsConfirmedService::from_response_tag(service_num);

    let mut get_name_list_info = None;
    let mut get_named_var_list_attr_info = None;
    let mut read_info = None;
    let mut get_var_access_attr_info = None;
    let mut write_info = None;
    let mut file_open_info = None;
    let mut file_read_info = None;
    if service == MmsConfirmedService::GetNameList {
        get_name_list_info = Some(super::name_services::parse_get_name_list_response(
            service_content,
            depth + 1,
        ));
    } else if service == MmsConfirmedService::GetNamedVariableListAttributes {
        get_named_var_list_attr_info = Some(
            super::name_services::parse_get_named_var_list_attr_response(
                service_content,
                depth + 1,
            ),
        );
    } else if service == MmsConfirmedService::Read {
        read_info = Some(super::read_write::parse_read_response(
            service_content,
            depth + 1,
        ));
    } else if service == MmsConfirmedService::GetVariableAccessAttributes {
        get_var_access_attr_info = Some(super::name_services::parse_get_var_access_attr_response(
            service_content,
            depth + 1,
        ));
    } else if service == MmsConfirmedService::Write {
        write_info = Some(super::read_write::parse_write_response(
            service_content,
            depth + 1,
        ));
    } else if service == MmsConfirmedService::FileOpen {
        file_open_info = super::file_services::parse_file_open_response(service_content, depth + 1);
    } else if service == MmsConfirmedService::FileRead {
        file_read_info = super::file_services::parse_file_read_response(service_content, depth + 1);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confirmed_request_missing_service_fails_contract() {
        let input = &[0x02, 0x01, 0x2A];
        assert!(parse_confirmed_request(input, 0).is_err());
    }

    #[test]
    fn test_confirmed_response_invoke_id_only_contract() {
        let input = &[0x02, 0x01, 0x2A];
        let pdu = parse_confirmed_response(input, 0).expect("invoke-id-only response parses");
        assert_eq!(pdu.pdu_type_str(), "confirmed_response");
        assert_eq!(pdu.service_str(), Some("unknown"));
        assert_eq!(pdu.invoke_id(), Some(42));
    }
}
