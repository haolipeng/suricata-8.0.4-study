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

//! TPKT and COTP frame parsers for IEC 61850 MMS.
//!
//! Protocol stack:
//!   TCP -> TPKT (RFC 1006) -> COTP (ISO 8073) -> MMS PDU

use nom7::bytes::streaming::take;
use nom7::number::streaming::be_u16;
use nom7::IResult;

/// TPKT header: 4 bytes
///   - version: 1 byte (must be 3)
///   - reserved: 1 byte (must be 0)
///   - length: 2 bytes (big-endian, total length including header)
pub const TPKT_HEADER_LEN: usize = 4;
pub const TPKT_VERSION: u8 = 3;

#[derive(Debug, PartialEq)]
pub struct TpktHeader {
    pub version: u8,
    pub length: u16,
}

/// COTP PDU 类型（ISO 8073）
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CotpPduType {
    ConnectionRequest,  // CR (0xE0)
    ConnectionConfirm,  // CC (0xD0)
    DisconnectRequest,  // DR (0x80)
    DataTransfer,       // DT (0xF0)
    Unknown(u8),
}

impl CotpPduType {
    fn from_byte(b: u8) -> Self {
        // PDU 类型由字节高 4 位决定（低 4 位含 CDT 信用值等）
        match b & 0xF0 {
            0xE0 => CotpPduType::ConnectionRequest,
            0xD0 => CotpPduType::ConnectionConfirm,
            0x80 => CotpPduType::DisconnectRequest,
            0xF0 => CotpPduType::DataTransfer,
            _ => CotpPduType::Unknown(b),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct CotpHeader {
    pub length: u8,
    pub pdu_type: CotpPduType,
    pub tpdu_nr: u8,     // TPDU 序号（仅 DT 帧有效）
    pub last_unit: bool,  // EOT 标志，true 表示本 TPDU 是 TSDU 的最后一个分片
}

/// Parsed result of one TPKT/COTP frame
#[derive(Debug, PartialEq)]
pub struct TpktCotpFrame<'a> {
    pub tpkt: TpktHeader,
    pub cotp: CotpHeader,
    /// The payload after COTP header (MMS PDU data for DT frames)
    pub payload: &'a [u8],
}

/// Parse a TPKT header.
pub fn parse_tpkt_header(i: &[u8]) -> IResult<&[u8], TpktHeader> {
    let (i, version) = nom7::number::streaming::u8(i)?;
    let (i, _reserved) = nom7::number::streaming::u8(i)?;
    let (i, length) = be_u16(i)?;
    Ok((i, TpktHeader { version, length }))
}

/// Parse a COTP header. The `available` parameter is the number of bytes
/// available in the TPKT payload (after the 4-byte TPKT header).
pub fn parse_cotp_header(i: &[u8]) -> IResult<&[u8], CotpHeader> {
    let (i, length) = nom7::number::streaming::u8(i)?;
    let (i, pdu_type_byte) = nom7::number::streaming::u8(i)?;
    let pdu_type = CotpPduType::from_byte(pdu_type_byte);

    match pdu_type {
        CotpPduType::DataTransfer => {
            // DT 帧格式：length(1) + type(1) + nr_and_eot(1)，之后是数据载荷
            let (i, nr_and_eot) = nom7::number::streaming::u8(i)?;
            let last_unit = (nr_and_eot & 0x80) != 0; // 最高位 = EOT
            let tpdu_nr = nr_and_eot & 0x7F;          // 低 7 位 = 序号
            // Skip any remaining COTP header bytes (length includes pdu_type byte)
            let remaining_header = if length > 2 { length - 2 } else { 0 };
            let (i, _) = take(remaining_header as usize)(i)?;
            Ok((
                i,
                CotpHeader {
                    length,
                    pdu_type,
                    tpdu_nr,
                    last_unit,
                },
            ))
        }
        _ => {
            // CR/CC/DR 帧：length 字段后的字节全属于 COTP 头部参数，直接跳过
            let remaining = if length > 1 { length - 1 } else { 0 };
            let (i, _) = take(remaining as usize)(i)?;
            Ok((
                i,
                CotpHeader {
                    length,
                    pdu_type,
                    tpdu_nr: 0,
                    last_unit: true,
                },
            ))
        }
    }
}

/// Parse a complete TPKT + COTP frame, returning the MMS payload.
///
/// Uses streaming parsers so incomplete data returns `Incomplete`.
pub fn parse_tpkt_cotp_frame(i: &[u8]) -> IResult<&[u8], TpktCotpFrame<'_>> {
    let (i, tpkt) = parse_tpkt_header(i)?;

    // Validate TPKT
    if tpkt.version != TPKT_VERSION {
        return Err(nom7::Err::Error(nom7::error::Error::new(
            i,
            nom7::error::ErrorKind::Verify,
        )));
    }
    if (tpkt.length as usize) < TPKT_HEADER_LEN {
        return Err(nom7::Err::Error(nom7::error::Error::new(
            i,
            nom7::error::ErrorKind::Verify,
        )));
    }

    // TPKT 长度包含自身 4 字节头，载荷长度 = total - 4
    let payload_len = tpkt.length as usize - TPKT_HEADER_LEN;

    // 精确提取 TPKT 载荷，剩余字节留给下一帧
    let (remaining, tpkt_payload) = take(payload_len)(i)?;

    // Parse COTP from the TPKT payload
    let (mms_payload, cotp) = parse_cotp_header(tpkt_payload)?;

    Ok((
        remaining,
        TpktCotpFrame {
            tpkt,
            cotp,
            payload: mms_payload,
        },
    ))
}

/// Probe function: check if input looks like a TPKT frame.
///
/// Returns true if the first bytes match TPKT version=3, reserved=0,
/// and length >= 7 (minimum: 4-byte TPKT + 3-byte COTP DT).
pub fn probe_tpkt(input: &[u8]) -> bool {
    input.len() >= TPKT_HEADER_LEN
        && input[0] == TPKT_VERSION
        && input[1] == 0x00
        && {
            let length = u16::from_be_bytes([input[2], input[3]]);
            length >= 7 && length < 65530
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_tpkt_valid() {
        // version=3, reserved=0, length=7 (minimum valid)
        assert!(probe_tpkt(&[0x03, 0x00, 0x00, 0x07]));
        // version=3, reserved=0, length=100
        assert!(probe_tpkt(&[0x03, 0x00, 0x00, 0x64]));
    }

    #[test]
    fn test_probe_tpkt_invalid() {
        // Too short
        assert!(!probe_tpkt(&[0x03, 0x00, 0x00]));
        // Wrong version
        assert!(!probe_tpkt(&[0x02, 0x00, 0x00, 0x07]));
        // Reserved not 0
        assert!(!probe_tpkt(&[0x03, 0x01, 0x00, 0x07]));
        // Length too small
        assert!(!probe_tpkt(&[0x03, 0x00, 0x00, 0x04]));
    }

    #[test]
    fn test_parse_tpkt_header() {
        let buf = [0x03, 0x00, 0x00, 0x1F, 0xAA];
        let (rem, hdr) = parse_tpkt_header(&buf).unwrap();
        assert_eq!(hdr.version, 3);
        assert_eq!(hdr.length, 31);
        assert_eq!(rem, &[0xAA]);
    }

    #[test]
    fn test_parse_cotp_dt() {
        // COTP DT: length=2, pdu_type=0xF0, last_unit=1 (tpdu_nr=0, eot=1)
        let buf = [0x02, 0xF0, 0x80, 0xAA, 0xBB];
        let (rem, cotp) = parse_cotp_header(&buf).unwrap();
        assert_eq!(cotp.pdu_type, CotpPduType::DataTransfer);
        assert!(cotp.last_unit);
        assert_eq!(cotp.tpdu_nr, 0);
        assert_eq!(rem, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_parse_tpkt_cotp_frame() {
        // TPKT: version=3, reserved=0, length=11
        // COTP DT: length=2, type=0xF0, eot=0x80
        // Payload: 4 bytes of MMS data
        let buf = [
            0x03, 0x00, 0x00, 0x0B, // TPKT header (length=11)
            0x02, 0xF0, 0x80, // COTP DT header
            0xA0, 0x03, 0x01, 0x02, // MMS payload
        ];
        let (rem, frame) = parse_tpkt_cotp_frame(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(frame.tpkt.version, 3);
        assert_eq!(frame.tpkt.length, 11);
        assert_eq!(frame.cotp.pdu_type, CotpPduType::DataTransfer);
        assert!(frame.cotp.last_unit);
        assert_eq!(frame.payload, &[0xA0, 0x03, 0x01, 0x02]);
    }

    #[test]
    fn test_parse_cotp_cr() {
        // COTP CR: length=6, pdu_type=0xE0, then 5 more bytes of header
        let buf = [0x06, 0xE0, 0x00, 0x01, 0x00, 0x02, 0xC0, 0xAA];
        let (rem, cotp) = parse_cotp_header(&buf).unwrap();
        assert_eq!(cotp.pdu_type, CotpPduType::ConnectionRequest);
        assert!(cotp.last_unit);
        // remaining bytes after COTP header should be just 0xAA
        assert_eq!(rem, &[0xAA]);
    }

    #[test]
    fn test_parse_incomplete() {
        // Only 2 bytes of TPKT header (needs 4)
        let buf = [0x03, 0x00];
        let result = parse_tpkt_header(&buf);
        assert!(result.is_err());
        if let Err(nom7::Err::Incomplete(_)) = result {
            // Expected
        } else {
            panic!("Expected Incomplete error");
        }
    }
}
