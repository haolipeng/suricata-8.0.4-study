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

//! APCI frame parser for IEC 60870-5-104.
//!
//! IEC 104 APDU format:
//!   Start byte (0x68) | APDU length (1 byte) | Control fields (4 bytes) | [ASDU]
//!
//! Frame types determined by control field byte 1:
//!   - I-frame: bit0 = 0 (information transfer, contains ASDU)
//!   - S-frame: bit0 = 1, bit1 = 0 (supervisory)
//!   - U-frame: bit0 = 1, bit1 = 1 (unnumbered control)

use nom7::bytes::streaming::take;
use nom7::number::streaming::le_u8;
use nom7::IResult;

/// IEC 104 start byte
pub const IEC104_START: u8 = 0x68;

/// Minimum APDU length (4 bytes control field only, for S/U frames)
pub const APDU_MIN_LEN: u8 = 4;

/// Maximum APDU length per specification
pub const APDU_MAX_LEN: u8 = 253;

/// U-frame function types
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum UFrameFunction {
    StartDtAct,
    StartDtCon,
    StopDtAct,
    StopDtCon,
    TestFrAct,
    TestFrCon,
}

impl UFrameFunction {
    pub fn as_str(&self) -> &'static str {
        match self {
            UFrameFunction::StartDtAct => "STARTDT_ACT",
            UFrameFunction::StartDtCon => "STARTDT_CON",
            UFrameFunction::StopDtAct => "STOPDT_ACT",
            UFrameFunction::StopDtCon => "STOPDT_CON",
            UFrameFunction::TestFrAct => "TESTFR_ACT",
            UFrameFunction::TestFrCon => "TESTFR_CON",
        }
    }

    /// Parse from control field byte 1.
    /// Bits: TESTFR_CON(7) TESTFR_ACT(6) STOPDT_CON(5) STOPDT_ACT(4)
    ///       STARTDT_CON(3) STARTDT_ACT(2) 1 1
    pub fn from_byte(b: u8) -> Option<UFrameFunction> {
        match b & 0xFC {
            0x04 => Some(UFrameFunction::StartDtAct),
            0x08 => Some(UFrameFunction::StartDtCon),
            0x10 => Some(UFrameFunction::StopDtAct),
            0x20 => Some(UFrameFunction::StopDtCon),
            0x40 => Some(UFrameFunction::TestFrAct),
            0x80 => Some(UFrameFunction::TestFrCon),
            _ => None, // multiple bits set or unknown
        }
    }
}

/// Parsed APCI frame
#[derive(Debug, PartialEq, Clone)]
pub enum ApciFrame {
    /// I-frame: information transfer with ASDU payload
    IFrame {
        send_seq: u16,
        recv_seq: u16,
        asdu_data: Vec<u8>,
    },
    /// S-frame: supervisory (acknowledge only)
    SFrame {
        recv_seq: u16,
    },
    /// U-frame: unnumbered control
    UFrame {
        function: UFrameFunction,
    },
}

impl ApciFrame {
    /// Return the frame type as a string
    pub fn frame_type_str(&self) -> &'static str {
        match self {
            ApciFrame::IFrame { .. } => "I",
            ApciFrame::SFrame { .. } => "S",
            ApciFrame::UFrame { .. } => "U",
        }
    }
}

/// Probe function: check if input looks like an IEC 104 APDU.
///
/// Returns true if start byte is 0x68 and length is in valid range [4, 253].
pub fn probe_iec104(input: &[u8]) -> bool {
    if input.len() < 2 {
        return false;
    }
    input[0] == IEC104_START && input[1] >= APDU_MIN_LEN && input[1] <= APDU_MAX_LEN
}

/// Parse a single IEC 104 APCI frame (streaming parser).
///
/// Format: 0x68 | length | control_1 | control_2 | control_3 | control_4 | [ASDU...]
pub fn parse_apci_frame(i: &[u8]) -> IResult<&[u8], ApciFrame> {
    // Start byte
    let (i, start) = le_u8(i)?;
    if start != IEC104_START {
        return Err(nom7::Err::Error(nom7::error::Error::new(
            i,
            nom7::error::ErrorKind::Verify,
        )));
    }

    // APDU length
    let (i, apdu_len) = le_u8(i)?;
    if apdu_len < APDU_MIN_LEN {
        return Err(nom7::Err::Error(nom7::error::Error::new(
            i,
            nom7::error::ErrorKind::Verify,
        )));
    }

    // Take exactly apdu_len bytes (control fields + optional ASDU)
    let (remaining, apdu_payload) = take(apdu_len as usize)(i)?;

    // Parse control fields (first 4 bytes)
    let ctrl1 = apdu_payload[0];
    let ctrl2 = apdu_payload[1];
    let ctrl3 = apdu_payload[2];
    let ctrl4 = apdu_payload[3];

    let frame = if ctrl1 & 0x01 == 0 {
        // I-frame: bit0 of ctrl1 = 0
        let send_seq = ((ctrl1 as u16) >> 1) | ((ctrl2 as u16) << 7);
        let recv_seq = ((ctrl3 as u16) >> 1) | ((ctrl4 as u16) << 7);
        let asdu_data = apdu_payload[4..].to_vec();
        ApciFrame::IFrame {
            send_seq,
            recv_seq,
            asdu_data,
        }
    } else if ctrl1 & 0x03 == 0x01 {
        // S-frame: bit0=1, bit1=0
        let recv_seq = ((ctrl3 as u16) >> 1) | ((ctrl4 as u16) << 7);
        ApciFrame::SFrame { recv_seq }
    } else {
        // U-frame: bit0=1, bit1=1
        let function = UFrameFunction::from_byte(ctrl1);
        match function {
            Some(f) => ApciFrame::UFrame { function: f },
            None => {
                // Unknown U-frame function - still parse but return error
                return Err(nom7::Err::Error(nom7::error::Error::new(
                    remaining,
                    nom7::error::ErrorKind::Verify,
                )));
            }
        }
    };

    Ok((remaining, frame))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_valid() {
        // Start=0x68, length=4 (minimum S/U frame)
        assert!(probe_iec104(&[0x68, 0x04, 0x01, 0x00, 0x00, 0x00]));
        // Start=0x68, length=14 (I-frame with 10-byte ASDU)
        assert!(probe_iec104(&[0x68, 0x0E]));
        // Start=0x68, length=253 (maximum)
        assert!(probe_iec104(&[0x68, 0xFD]));
    }

    #[test]
    fn test_probe_invalid() {
        // Too short
        assert!(!probe_iec104(&[0x68]));
        // Wrong start byte
        assert!(!probe_iec104(&[0x69, 0x04]));
        // Length too small
        assert!(!probe_iec104(&[0x68, 0x03]));
        // Empty
        assert!(!probe_iec104(&[]));
    }

    #[test]
    fn test_parse_u_frame_startdt_act() {
        // STARTDT act: 0x68 0x04 0x07 0x00 0x00 0x00
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let (rem, frame) = parse_apci_frame(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            frame,
            ApciFrame::UFrame {
                function: UFrameFunction::StartDtAct
            }
        );
        assert_eq!(frame.frame_type_str(), "U");
    }

    #[test]
    fn test_parse_u_frame_startdt_con() {
        // STARTDT con: 0x68 0x04 0x0B 0x00 0x00 0x00
        let buf = [0x68, 0x04, 0x0B, 0x00, 0x00, 0x00];
        let (rem, frame) = parse_apci_frame(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            frame,
            ApciFrame::UFrame {
                function: UFrameFunction::StartDtCon
            }
        );
    }

    #[test]
    fn test_parse_u_frame_testfr_act() {
        // TESTFR act: 0x68 0x04 0x43 0x00 0x00 0x00
        let buf = [0x68, 0x04, 0x43, 0x00, 0x00, 0x00];
        let (rem, frame) = parse_apci_frame(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            frame,
            ApciFrame::UFrame {
                function: UFrameFunction::TestFrAct
            }
        );
    }

    #[test]
    fn test_parse_u_frame_testfr_con() {
        // TESTFR con: 0x68 0x04 0x83 0x00 0x00 0x00
        let buf = [0x68, 0x04, 0x83, 0x00, 0x00, 0x00];
        let (rem, frame) = parse_apci_frame(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            frame,
            ApciFrame::UFrame {
                function: UFrameFunction::TestFrCon
            }
        );
    }

    #[test]
    fn test_parse_s_frame() {
        // S-frame: 0x68 0x04 0x01 0x00 0x0A 0x00 (recv_seq=5)
        let buf = [0x68, 0x04, 0x01, 0x00, 0x0A, 0x00];
        let (rem, frame) = parse_apci_frame(&buf).unwrap();
        assert!(rem.is_empty());
        assert_eq!(frame, ApciFrame::SFrame { recv_seq: 5 });
        assert_eq!(frame.frame_type_str(), "S");
    }

    #[test]
    fn test_parse_i_frame() {
        // I-frame with send_seq=0, recv_seq=0, 10-byte ASDU
        let mut buf = vec![
            0x68, 0x0E, // start, length=14
            0x00, 0x00, // ctrl1/2: send_seq=0
            0x00, 0x00, // ctrl3/4: recv_seq=0
        ];
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
        let (rem, frame) = parse_apci_frame(&buf).unwrap();
        assert!(rem.is_empty());
        match frame {
            ApciFrame::IFrame {
                send_seq,
                recv_seq,
                ref asdu_data,
            } => {
                assert_eq!(send_seq, 0);
                assert_eq!(recv_seq, 0);
                assert_eq!(asdu_data.len(), 10);
                assert_eq!(asdu_data[0], 0x01);
            }
            _ => panic!("Expected I-frame"),
        }
        assert_eq!(frame.frame_type_str(), "I");
    }

    #[test]
    fn test_parse_i_frame_with_sequence_numbers() {
        // I-frame: send_seq=1 (0x02,0x00), recv_seq=3 (0x06,0x00)
        let buf = [
            0x68, 0x0E, // start, length=14
            0x02, 0x00, // send_seq=1
            0x06, 0x00, // recv_seq=3
            // 10-byte dummy ASDU
            0x0D, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x00,
        ];
        let (rem, frame) = parse_apci_frame(&buf).unwrap();
        assert!(rem.is_empty());
        match frame {
            ApciFrame::IFrame {
                send_seq,
                recv_seq,
                ..
            } => {
                assert_eq!(send_seq, 1);
                assert_eq!(recv_seq, 3);
            }
            _ => panic!("Expected I-frame"),
        }
    }

    #[test]
    fn test_parse_incomplete() {
        // Only start byte and length, no control fields
        let buf = [0x68, 0x04];
        let result = parse_apci_frame(&buf);
        assert!(result.is_err());
        if let Err(nom7::Err::Incomplete(_)) = result {
            // Expected
        } else {
            panic!("Expected Incomplete error");
        }
    }

    #[test]
    fn test_parse_wrong_start_byte() {
        let buf = [0x69, 0x04, 0x07, 0x00, 0x00, 0x00];
        let result = parse_apci_frame(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_multiple_frames() {
        // Two U-frames back-to-back
        let buf = [
            0x68, 0x04, 0x07, 0x00, 0x00, 0x00, // STARTDT act
            0x68, 0x04, 0x0B, 0x00, 0x00, 0x00, // STARTDT con
        ];
        let (rem, frame1) = parse_apci_frame(&buf).unwrap();
        assert_eq!(
            frame1,
            ApciFrame::UFrame {
                function: UFrameFunction::StartDtAct
            }
        );
        assert_eq!(rem.len(), 6);

        let (rem2, frame2) = parse_apci_frame(rem).unwrap();
        assert!(rem2.is_empty());
        assert_eq!(
            frame2,
            ApciFrame::UFrame {
                function: UFrameFunction::StartDtCon
            }
        );
    }
}
