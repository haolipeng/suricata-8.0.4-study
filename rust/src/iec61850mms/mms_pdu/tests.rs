use super::*;

// ====== Refactor guard tests: top-level parser contract ======

#[test]
fn test_parse_mms_pdu_top_level_smoke_contract() {
    let cases: Vec<(&[u8], &'static str, Option<&'static str>, Option<u32>)> = vec![
        (
            &[0xA8, 0x03, 0x80, 0x01, 0x01],
            "initiate_request",
            None,
            None,
        ),
        (
            &[
                0xA0, 0x0A, // confirmed request
                0x02, 0x01, 0x2A, // invokeID = 42
                0xA4, 0x05, // Read
                0xA1, 0x03, 0xA0, 0x01, 0x00,
            ],
            "confirmed_request",
            Some("read"),
            Some(42),
        ),
        (
            &[
                0xA1, 0x07, // confirmed response
                0x02, 0x01, 0x2A, // invokeID = 42
                0xA4, 0x02, 0xA0, 0x00, // Read response
            ],
            "confirmed_response",
            Some("read"),
            Some(42),
        ),
        (
            &[0xA3, 0x04, 0xA0, 0x02, 0x30, 0x00],
            "unconfirmed",
            Some("information_report"),
            None,
        ),
        (
            &[
                0xA0, 0x11, // confirmed request
                0x02, 0x01, 0x05, // invokeID = 5
                0xBF, 0x49, 0x0B, // FileOpen [73]
                0xA0, 0x06, // fileName
                0x1A, 0x04, b't', b'e', b's', b't', 0x81, 0x01, 0x00, // initialPosition
            ],
            "confirmed_request",
            Some("file_open"),
            Some(5),
        ),
    ];

    for (input, expected_pdu_type, expected_service, expected_invoke_id) in cases {
        let pdu = parse_mms_pdu(input).expect("smoke PDU should parse");
        assert_eq!(pdu.pdu_type_str(), expected_pdu_type);
        assert_eq!(pdu.service_str(), expected_service);
        assert_eq!(pdu.invoke_id(), expected_invoke_id);
    }
}

#[test]
fn test_parse_mms_pdu_negative_boundary_contract() {
    let cases: Vec<&[u8]> = vec![
        &[],                       // empty input
        &[0xA0],                   // missing BER length
        &[0xA0, 0x10, 0x02, 0x01], // top-level length exceeds input
        &[0xAE, 0x00],             // context tag [14] is outside MMS-PDU CHOICE
        &[0xA0, 0x00],             // confirmed request missing invokeID/service
        &[0x02, 0x01, 0x01],       // universal INTEGER is not an MMS-PDU
        &[0x6B, 0x00],             // application-class tag [11] must not parse as ConcludeRequest
        &[0xCB, 0x00],             // private-class tag [11] must not parse as ConcludeRequest
        &[0x80, 0x00],             // ConfirmedRequest must be constructed [0], not primitive [0]
    ];

    for input in cases {
        assert!(
            parse_mms_pdu(input).is_err(),
            "input should fail: {:02x?}",
            input
        );
    }
}

#[test]
fn test_parse_mms_pdu_typed_error_contract() {
    assert!(matches!(
        parse_mms_pdu_typed(&[]),
        Err(MmsParseError::Malformed("empty MMS PDU"))
    ));

    assert!(matches!(
        parse_mms_pdu_typed(&[0x02, 0x01, 0x01]),
        Err(MmsParseError::SemanticViolation(
            "invalid top-level MMS PDU tag"
        ))
    ));

    assert_eq!(parse_mms_pdu(&[0x02, 0x01, 0x01]), Err(()));
}

#[test]
fn test_parse_mms_pdu_typed_preserves_child_error_contract() {
    assert!(matches!(
        parse_mms_pdu_typed(&[0xA0, 0x00]),
        Err(MmsParseError::Malformed(
            "missing confirmed request invoke-id"
        ))
    ));

    assert!(matches!(
        parse_mms_pdu_typed(&[0xA0, 0x03, 0x02, 0x01, 0x01]),
        Err(MmsParseError::Malformed(
            "missing confirmed request service"
        ))
    ));

    assert!(matches!(
        parse_mms_pdu_typed(&[0xA3, 0x00]),
        Err(MmsParseError::Malformed("missing unconfirmed service"))
    ));
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
    let data = &[0x8B, 0x00];
    let result = parse_mms_pdu(data);
    assert!(result.is_ok(), "should parse conclude request: {:02x?}", data);
    assert_eq!(result.unwrap(), MmsPdu::ConcludeRequest);
}

#[test]
fn test_parse_conclude_response() {
    let data = &[0x8C, 0x00];
    let result = parse_mms_pdu(data);
    assert!(result.is_ok(), "should parse conclude response: {:02x?}", data);
    assert_eq!(result.unwrap(), MmsPdu::ConcludeResponse);
}

#[test]
fn test_parse_cancel_request() {
    for data in [&[0x85, 0x01, 0x2A][..], &[0xA5, 0x01, 0x2A][..]] {
        let result = parse_mms_pdu(data);
        assert!(result.is_ok(), "should parse cancel request: {:02x?}", data);
        assert_eq!(result.unwrap(), MmsPdu::CancelRequest { invoke_id: 42 });
    }
}

#[test]
fn test_parse_cancel_response() {
    for data in [&[0x86, 0x01, 0x2A][..], &[0xA6, 0x01, 0x2A][..]] {
        let result = parse_mms_pdu(data);
        assert!(result.is_ok(), "should parse cancel response: {:02x?}", data);
        assert_eq!(result.unwrap(), MmsPdu::CancelResponse { invoke_id: 42 });
    }
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
        MmsPdu::ConfirmedResponse {
            invoke_id, service, ..
        } => {
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
        0xA2, 0x0A, // [2] serviceError
        0xA0, 0x08, //   [0] errorClass
        0x87, 0x01, 0x02, //     [7] access = 2 (object-non-existent)
        // 后续可能有 additionalCode 等，此处省略
        0x00, 0x00, 0x00, 0x00, 0x00, // padding (不影响解析)
    ];
    let result = parse_mms_pdu(data).unwrap();
    match result {
        MmsPdu::ConfirmedError {
            invoke_id,
            error_class,
            error_code,
        } => {
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
        MmsPdu::ConfirmedError {
            invoke_id,
            error_class,
            error_code,
        } => {
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
        0xA2, 0x0C, // [2] Confirmed-ErrorPDU, length=12
        0x80, 0x03, 0x04, 0xA2, 0x73, // [0] invokeID = 303731
        0xA2, 0x05, // [2] serviceError
        0xA0, 0x03, //   [0] errorClass
        0x87, 0x01, 0x02, //     [7] access = 2
    ];
    let result = parse_mms_pdu(data).unwrap();
    match result {
        MmsPdu::ConfirmedError {
            invoke_id,
            error_class,
            error_code,
        } => {
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
        0x81, 0x01, 0x05, // [1] maxServOutstandingCalling = 5
        0x82, 0x01, 0x05, // [2] maxServOutstandingCalled = 5
        0x83, 0x01, 0x0A, // [3] nestingLevel = 10
        0xA4, 0x0D, // [4] initRequestDetail
        0x80, 0x01, 0x01, //   [0] versionNumber = 1
        0x81, 0x03, 0x00, 0xFB, 0x00, //   [1] parameterCBB (ignored)
        0x82, 0x03, 0x00, 0xEE,
        0x1C, //   [2] servicesSupportedCalling (BIT STRING: 0 unused + EE 1C)
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
        0x81, 0x01, 0x05, // [1] maxServOutstandingCalling = 5
        0x82, 0x01, 0x05, // [2] maxServOutstandingCalled = 5
        0x83, 0x01, 0x04, // [3] nestingLevel = 4
        0xA4, 0x07, // [4] initRequestDetail
        0x80, 0x01, 0x01, //   [0] versionNumber = 1
        0x82, 0x02, 0x00,
        0xFF, //   [2] servicesSupportedCalling (BIT STRING: 0 unused bits + 0xFF)
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
        0x81, 0x01, 0x05, // [1] maxServOutstandingCalling = 5
        0x82, 0x01, 0x05, // [2] maxServOutstandingCalled = 5
        0xA4, 0x03, // [4] initResponseDetail
        0x80, 0x01, 0x01, //   [0] versionNumber = 1
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
        0xA0, 22, // ConfirmedRequestPDU [0]
        0x02, 1, 1, // invokeID = 1
        0xAC, 17, // [12] getNamedVariableListAttributes
        // ObjectName: domain-specific [1] SEQUENCE
        0xA1, 15, 0x1A, 4, b'D', b'O', b'M', b'1', // domainId = "DOM1"
        0x1A, 7, b'L', b'L', b'N', b'0', b'$', b'D', b'S', // itemId = "LLN0$DS"
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
            assert_eq!(
                *service,
                MmsConfirmedService::GetNamedVariableListAttributes
            );
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
        0xA0, 11, // ConfirmedRequestPDU [0]
        0x02, 1, 2, // invokeID = 2
        0xAC, 6, // [12] getNamedVariableListAttributes
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
        0xA1, 38, // ConfirmedResponsePDU [1]
        0x02, 1, 1, // invokeID = 1
        0xAC, 33, // [12] getNamedVariableListAttributes
        // mmsDeletable [0] IMPLICIT BOOLEAN = FALSE
        0x80, 1, 0x00, // listOfVariable [1] IMPLICIT SEQUENCE OF
        0xA1, 28, // item 1: SEQUENCE { variableSpecification: name [0] ObjectName }
        0x30, 12, 0xA0, 10, // name [0]
        0xA1, 8, // domain-specific [1]
        0x1A, 1, b'D', // domainId = "D"
        0x1A, 3, b'V', b'_', b'1', // itemId = "V_1"
        // item 2
        0x30, 12, 0xA0, 10, // name [0]
        0xA1, 8, // domain-specific [1]
        0x1A, 1, b'D', // domainId = "D"
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
            assert_eq!(
                *service,
                MmsConfirmedService::GetNamedVariableListAttributes
            );
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
        0x1A, 0x03, 0x4D, 0x6F, 0x64, // VisibleString "Mod"
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
            assert_eq!(
                wi.variable_specs.len(),
                64,
                "Should truncate to 64, got {}",
                wi.variable_specs.len()
            );
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
        &[
            0xA0, 0x0A, 0x02, 0x01, 0x01, 0xA5, 0x05, 0xA0, 0x03, 0xFF, 0xFF, 0xFF,
        ],
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
                assert!(wi.variable_specs.len() <= 64, "Case {}: too many specs", i);
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
        0xA0, 0x07, 0x30, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x56, // listOfData [0]
        0xA0, 0x0B, // structure [2] with 3 members
        0xA2, 0x09, 0x83, 0x01, 0x01, // boolean true
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
        0xA0, 0x07, 0x30, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x56, // listOfData [0]
        0xA0, 0x06, 0x85, 0x01, 0xFD, // integer -3
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
        MmsPdu::ConfirmedResponse {
            invoke_id,
            service,
            write_info,
            ..
        } => {
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
        MmsPdu::ConfirmedRequest {
            invoke_id,
            service,
            file_open_info,
            ..
        } => {
            assert_eq!(*invoke_id, 5);
            assert_eq!(*service, MmsConfirmedService::FileOpen);
            let fo = file_open_info
                .as_ref()
                .expect("file_open_info should be Some");
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
            let fo = file_open_info
                .as_ref()
                .expect("file_open_info should be Some");
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
            assert_eq!(
                fo.initial_position, 0,
                "missing initialPosition should default to 0"
            );
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
            assert!(
                fo.file_name.is_empty(),
                "empty segments should produce empty file_name"
            );
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
        &[
            0xA0, 0x08, 0x02, 0x01, 0x01, 0xBF, 0x49, 0x03, 0x81, 0x01, 0x00,
        ],
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
        &[0xA1, 0x20][..],         // [1] ConfirmedResponse, len=32
        &[0x02, 0x01, 0x03],       // invokeID = 3
        &[0xBF, 0x49, 0x1A],       // [73] FileOpen, len=26
        &[0x80, 0x01, 0x07],       // frsmID [0] = 7
        &[0xA1, 0x15],             // fileAttributes [1], len=21
        &[0x80, 0x02, 0x10, 0x00], // sizeOfFile [0] = 4096
        &[0x81, 0x0F],             // lastModified [1], len=15
        last_mod,
    ]
    .concat();

    let pdu = parse_mms_pdu(&data).expect("should parse FileOpen response");
    match &pdu {
        MmsPdu::ConfirmedResponse {
            invoke_id,
            service,
            file_open_info,
            ..
        } => {
            assert_eq!(*invoke_id, 3);
            assert_eq!(*service, MmsConfirmedService::FileOpen);
            let fo = file_open_info
                .as_ref()
                .expect("file_open_info should be Some");
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
        &[0x02, 0x01, 0x01],       // invokeID = 1
        &[0xBF, 0x49, 0x09],       // [73] FileOpen, len=9
        &[0x80, 0x01, 0x01],       // frsmID = 1
        &[0xA1, 0x04],             // fileAttributes, len=4
        &[0x80, 0x02, 0x01, 0x00], // sizeOfFile = 256
    ]
    .concat();

    let pdu = parse_mms_pdu(&data).expect("should parse");
    match &pdu {
        MmsPdu::ConfirmedResponse { file_open_info, .. } => {
            let fo = file_open_info.as_ref().expect("should have file_open_info");
            assert_eq!(fo.frsm_id, 1);
            assert_eq!(fo.file_size, Some(256));
            assert_eq!(
                fo.last_modified, None,
                "missing lastModified should be None"
            );
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
        MmsPdu::ConfirmedRequest {
            invoke_id,
            service,
            file_read_info,
            ..
        } => {
            assert_eq!(*invoke_id, 3);
            assert_eq!(*service, MmsConfirmedService::FileRead);
            let fr = file_read_info
                .as_ref()
                .expect("file_read_info should be Some");
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
        &[0xA1, 0x10][..],                           // [1] ConfirmedResponse, len=16
        &[0x02, 0x01, 0x01],                         // invokeID = 1
        &[0xBF, 0x4A, 0x0A],                         // [74] FileRead, len=10
        &[0x80, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05], // fileData [0], 5 bytes
        &[0x81, 0x01, 0x00],                         // moreFollows [1] = false
    ]
    .concat();

    let pdu = parse_mms_pdu(&data).expect("should parse FileRead response");
    match &pdu {
        MmsPdu::ConfirmedResponse {
            service,
            file_read_info,
            ..
        } => {
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
        MmsPdu::ConfirmedRequest {
            invoke_id,
            service,
            file_read_info,
            ..
        } => {
            assert_eq!(*invoke_id, 2);
            assert_eq!(*service, MmsConfirmedService::FileClose);
            let fr = file_read_info
                .as_ref()
                .expect("file_read_info should be Some");
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
        MmsPdu::ConfirmedResponse {
            invoke_id, service, ..
        } => {
            assert_eq!(*invoke_id, 2);
            assert_eq!(*service, MmsConfirmedService::FileClose);
        }
        _ => panic!("Expected ConfirmedResponse"),
    }
}
