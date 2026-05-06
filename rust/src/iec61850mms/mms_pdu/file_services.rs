//! MMS file service parsing.

use crate::iec61850mms::ber::{parse_ber_integer, parse_ber_string, parse_ber_tlv, MAX_BER_DEPTH};
use crate::iec61850mms::mms_types::*;

pub(super) fn parse_file_open_request(content: &[u8], depth: usize) -> Option<MmsFileOpenRequest> {
    if depth > MAX_BER_DEPTH || content.is_empty() {
        return None;
    }

    let (tag_byte, _, _, inner, rem) = parse_ber_tlv(content).ok()?;
    if tag_byte != 0xA0 {
        return None;
    }

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

    let mut initial_position = 0u32;
    if !rem.is_empty() {
        if let Ok((tag2, _, _, pos_content, _)) = parse_ber_tlv(rem) {
            if tag2 == 0x81 {
                initial_position = parse_ber_integer(pos_content).ok()?;
            }
        }
    }

    Some(MmsFileOpenRequest {
        file_name,
        initial_position,
    })
}

pub(super) fn parse_file_open_response(
    content: &[u8], depth: usize,
) -> Option<MmsFileOpenResponse> {
    if depth > MAX_BER_DEPTH || content.is_empty() {
        return None;
    }

    let (tag_byte, _, _, inner, rem) = parse_ber_tlv(content).ok()?;
    if tag_byte != 0x80 {
        return None;
    }
    let frsm_id = parse_ber_integer(inner).ok()?;

    let mut file_size = None;
    let mut last_modified = None;

    if !rem.is_empty() {
        if let Ok((tag2, _, _, attr_inner, _)) = parse_ber_tlv(rem) {
            if tag2 == 0xA1 {
                let mut pos = attr_inner;
                while !pos.is_empty() {
                    if let Ok((attr_tag, _, _, attr_content, attr_rem)) = parse_ber_tlv(pos) {
                        match attr_tag {
                            0x80 => {
                                file_size = Some(parse_ber_integer(attr_content).ok()?);
                            }
                            0x81 => {
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

pub(super) fn parse_file_read_response(
    content: &[u8], depth: usize,
) -> Option<MmsFileReadResponse> {
    if depth > MAX_BER_DEPTH || content.is_empty() {
        return None;
    }

    let (tag_byte, _, _, inner, rem) = parse_ber_tlv(content).ok()?;
    if tag_byte != 0x80 {
        return None;
    }
    let data_length = inner.len() as u32;

    let mut more_follows = true;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_file_open_request_path_and_position_contract() {
        let input = &[
            0xA0, 0x0C, // fileName SEQUENCE OF
            0x1A, 0x03, b's', b'u', b'b', 0x1A, 0x05, b'a', b'.', b'd', b'a', b't', 0x81, 0x01,
            0x64,
        ];

        let result = parse_file_open_request(input, 0).expect("file open request parses");
        assert_eq!(result.file_name, "sub/a.dat");
        assert_eq!(result.initial_position, 100);
    }

    #[test]
    fn test_parse_file_open_request_empty_segments_contract() {
        let input = &[
            0xA0, 0x00, // empty fileName
            0x81, 0x01, 0x00,
        ];

        let result = parse_file_open_request(input, 0).expect("empty file name still parses");
        assert!(result.file_name.is_empty());
        assert_eq!(result.initial_position, 0);
    }

    #[test]
    fn test_parse_file_open_request_missing_position_defaults_to_zero_contract() {
        let input = &[
            0xA0, 0x06, // fileName SEQUENCE OF
            0x1A, 0x04, b't', b'e', b's', b't',
        ];

        let result = parse_file_open_request(input, 0).expect("missing initialPosition is allowed");
        assert_eq!(result.file_name, "test");
        assert_eq!(result.initial_position, 0);
    }

    #[test]
    fn test_parse_file_open_request_malformed_position_is_not_defaulted_contract() {
        let input = &[
            0xA0, 0x06, // fileName SEQUENCE OF
            0x1A, 0x04, b't', b'e', b's', b't', 0x81, 0x00, // malformed initialPosition
        ];

        assert!(parse_file_open_request(input, 0).is_none());
    }

    #[test]
    fn test_parse_file_open_request_malformed_contract() {
        assert!(parse_file_open_request(&[], 0).is_none());
        assert!(parse_file_open_request(&[0x81, 0x01, 0x00], 0).is_none());
        assert!(parse_file_open_request(&[0xA0], 0).is_none());
    }

    #[test]
    fn test_parse_file_open_response_attributes_contract() {
        let input = &[
            0x80, 0x01, 0x07, // frsmID
            0xA1, 0x15, // fileAttributes
            0x80, 0x02, 0x10, 0x00, // sizeOfFile = 4096
            0x81, 0x0F, b'2', b'0', b'2', b'4', b'0', b'1', b'0', b'1', b'1', b'2', b'0', b'0',
            b'0', b'0', b'Z',
        ];

        let result = parse_file_open_response(input, 0).expect("file open response parses");
        assert_eq!(result.frsm_id, 7);
        assert_eq!(result.file_size, Some(4096));
        assert_eq!(result.last_modified.as_deref(), Some("20240101120000Z"));
    }

    #[test]
    fn test_parse_file_open_response_malformed_frsm_id_is_not_defaulted_contract() {
        let input = &[
            0x80, 0x00, // malformed frsmID
            0xA1, 0x04, 0x80, 0x02, 0x10, 0x00,
        ];

        assert!(parse_file_open_response(input, 0).is_none());
    }

    #[test]
    fn test_parse_file_open_response_malformed_file_size_is_not_dropped_contract() {
        let input = &[
            0x80, 0x01, 0x07, // frsmID
            0xA1, 0x02, // fileAttributes
            0x80, 0x00, // malformed sizeOfFile
        ];

        assert!(parse_file_open_response(input, 0).is_none());
    }

    #[test]
    fn test_parse_file_read_response_data_length_and_default_contract() {
        let with_more_follows = &[
            0x80, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, // fileData
            0x81, 0x01, 0x00, // moreFollows=false
        ];
        let default_more_follows = &[0x80, 0x02, 0xAA, 0xBB];

        let result =
            parse_file_read_response(with_more_follows, 0).expect("file read response parses");
        assert_eq!(result.data_length, 5);
        assert!(!result.more_follows);

        let result = parse_file_read_response(default_more_follows, 0)
            .expect("file read response with default moreFollows parses");
        assert_eq!(result.data_length, 2);
        assert!(result.more_follows);
    }
}
