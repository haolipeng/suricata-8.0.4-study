//! Miscellaneous MMS PDU parsing.

use super::error::{MmsParseError, MmsParseResult};
use crate::iec61850mms::ber::{parse_ber_integer, parse_ber_tlv, MAX_BER_DEPTH};
use crate::iec61850mms::mms_types::*;

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

fn error_code_name(error_class_tag: u32, code: u32) -> Option<&'static str> {
    match error_class_tag {
        0 => match code {
            0 => Some("other"),
            1 => Some("vmd-state-conflict"),
            2 => Some("vmd-operational-problem"),
            3 => Some("domain-transfer-problem"),
            4 => Some("state-machine-id-invalid"),
            _ => None,
        },
        1 => match code {
            0 => Some("other"),
            1 => Some("aplication-unreachable"),
            2 => Some("connection-lost"),
            3 => Some("application-reference-invalid"),
            4 => Some("context-unsupported"),
            _ => None,
        },
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
        3 => match code {
            0 => Some("other"),
            1 => Some("memory-unavailable"),
            2 => Some("processor-resource-unavailable"),
            3 => Some("mass-storage-unavailable"),
            4 => Some("capability-unavailable"),
            5 => Some("capability-unknown"),
            _ => None,
        },
        4 => match code {
            0 => Some("other"),
            1 => Some("primitives-out-of-sequence"),
            2 => Some("object-state-conflict"),
            3 => Some("pdu-size"),
            4 => Some("continuation-invalid"),
            5 => Some("object-constraint-conflict"),
            _ => None,
        },
        5 => match code {
            0 => Some("other"),
            1 => Some("timeout"),
            2 => Some("deadlock"),
            3 => Some("cancel"),
            _ => None,
        },
        6 => match code {
            0 => Some("other"),
            1 => Some("unsupportable-time-resolution"),
            _ => None,
        },
        7 => match code {
            0 => Some("other"),
            1 => Some("object-access-unsupported"),
            2 => Some("object-non-existent"),
            3 => Some("object-access-denied"),
            4 => Some("object-invalidated"),
            _ => None,
        },
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
        9 => match code {
            0 => Some("other"),
            1 => Some("further-communication-required"),
            _ => None,
        },
        10 => match code {
            0 => Some("other"),
            1 => Some("invoke-id-unknown"),
            2 => Some("cancel-not-possible"),
            _ => None,
        },
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
        12 => match code {
            0 => Some("other"),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn parse_confirmed_error(content: &[u8], depth: usize) -> MmsParseResult<MmsPdu> {
    if depth > MAX_BER_DEPTH {
        return Err(MmsParseError::depth_limit());
    }

    let mut invoke_id = 0u32;
    let mut error_class: Option<String> = None;
    let mut error_code: Option<String> = None;
    let mut pos = content;

    while !pos.is_empty() {
        let (tag_byte, _, tag_num, inner, rem) = parse_ber_tlv(pos)
            .map_err(|_| MmsParseError::malformed("invalid confirmed error field"))?;
        match tag_byte {
            0x02 | 0x80 => {
                invoke_id = parse_ber_integer(inner)
                    .map_err(|_| MmsParseError::malformed("invalid confirmed error invoke-id"))?;
            }
            0x81 => {}
            0xA2 => {
                if let Ok((_, _, _, error_class_content, _)) = parse_ber_tlv(inner) {
                    if let Ok((_, _, ec_tag_num, ec_inner, _)) = parse_ber_tlv(error_class_content)
                    {
                        error_class = error_class_tag_name(ec_tag_num).map(|s| s.to_string());
                        if let Ok(code) = parse_ber_integer(ec_inner) {
                            error_code = error_code_name(ec_tag_num, code)
                                .map(|s| s.to_string())
                                .or_else(|| Some(code.to_string()));
                        }
                    }
                }
            }
            _ => if tag_num == 0 && tag_byte == 0xA0 {},
        }
        pos = rem;
    }

    Ok(MmsPdu::ConfirmedError {
        invoke_id,
        error_class,
        error_code,
    })
}

pub(super) fn parse_unconfirmed_pdu(content: &[u8], depth: usize) -> MmsParseResult<MmsPdu> {
    if depth > MAX_BER_DEPTH {
        return Err(MmsParseError::depth_limit());
    }
    let (_, _, tag_num, _, _) = parse_ber_tlv(content)
        .map_err(|_| MmsParseError::malformed("missing unconfirmed service"))?;
    let service = MmsUnconfirmedService::from_tag(tag_num);
    Ok(MmsPdu::UnconfirmedPdu { service })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_confirmed_error_service_error_contract() {
        let input = &[
            0x80, 0x01, 0x05, // invokeID
            0xA2, 0x0A, // serviceError
            0xA0, 0x08, // errorClass
            0x87, 0x01, 0x02, // access = object-non-existent
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse_confirmed_error(input, 0).expect("confirmed error parses");
        match result {
            MmsPdu::ConfirmedError {
                invoke_id,
                error_class,
                error_code,
            } => {
                assert_eq!(invoke_id, 5);
                assert_eq!(error_class.as_deref(), Some("access"));
                assert_eq!(error_code.as_deref(), Some("object-non-existent"));
            }
            other => panic!("Expected ConfirmedError, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_confirmed_error_minimal_contract() {
        let input = &[0x80, 0x01, 0x09];

        let result = parse_confirmed_error(input, 0).expect("minimal confirmed error parses");
        match result {
            MmsPdu::ConfirmedError {
                invoke_id,
                error_class,
                error_code,
            } => {
                assert_eq!(invoke_id, 9);
                assert_eq!(error_class, None);
                assert_eq!(error_code, None);
            }
            other => panic!("Expected ConfirmedError, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_unconfirmed_pdu_service_contract() {
        let input = &[0xA0, 0x02, 0x30, 0x00];

        let result = parse_unconfirmed_pdu(input, 0).expect("unconfirmed PDU parses");
        match result {
            MmsPdu::UnconfirmedPdu { service } => {
                assert_eq!(service, MmsUnconfirmedService::InformationReport);
            }
            other => panic!("Expected UnconfirmedPdu, got {:?}", other),
        }
    }
}
