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

//! X11 protocol binary frame parser.
//!
//! Handles Connection Setup Request/Response parsing, request headers,
//! and server messages (Reply/Error/Event).

use nom7 as nom;
use nom::number::streaming::{be_u16, be_u32, le_u16, le_u32};
use nom::IResult;

/// X11 byte order, determined by the first byte of the Connection Setup Request.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum X11ByteOrder {
    BigEndian,    // 0x42 ('B')
    LittleEndian, // 0x6c ('l')
}

impl X11ByteOrder {
    pub fn read_u16<'a>(&self, input: &'a [u8]) -> IResult<&'a [u8], u16> {
        match self {
            X11ByteOrder::BigEndian => be_u16(input),
            X11ByteOrder::LittleEndian => le_u16(input),
        }
    }

    pub fn read_u32<'a>(&self, input: &'a [u8]) -> IResult<&'a [u8], u32> {
        match self {
            X11ByteOrder::BigEndian => be_u32(input),
            X11ByteOrder::LittleEndian => le_u32(input),
        }
    }
}

/// X11 Connection Setup Request from client.
#[derive(Debug, Clone)]
pub struct X11SetupRequest {
    pub byte_order: X11ByteOrder,
    pub major_version: u16,
    pub minor_version: u16,
    pub auth_protocol_name: String,
    pub auth_data_len: u16,
}

/// X11 Connection Setup Response from server.
#[derive(Debug, Clone)]
pub enum X11SetupResponse {
    Success {
        major_version: u16,
        minor_version: u16,
        release_number: u32,
        vendor: String,
        screen_count: u8,
    },
    Failed {
        major_version: u16,
        minor_version: u16,
        reason: String,
    },
    Authenticate {
        reason: String,
    },
}

/// X11 request header (Connected state, client → server).
#[derive(Debug, Clone)]
pub struct X11RequestHeader {
    pub opcode: u8,
    pub data: u8,
    pub length: u16, // in 4-byte units, including header
}

/// X11 server message types (Connected state, server → client).
#[derive(Debug, Clone)]
pub enum X11ServerMessage {
    Error {
        code: u8,
        sequence: u16,
        major_opcode: u8,
    },
    Reply {
        sequence: u16,
        length: u32, // additional data length in 4-byte units
    },
    Event {
        code: u8,
        sequence: u16,
    },
}

/// Calculate 4-byte alignment padding.
#[inline]
pub fn pad4(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// Probe input to determine if it looks like X11 Connection Setup Request.
/// Checks first byte (0x42 or 0x6c) and protocol version 11.0.
pub fn probe_x11(input: &[u8]) -> bool {
    if input.len() < 12 {
        return false;
    }
    let byte_order = match input[0] {
        0x42 => X11ByteOrder::BigEndian,
        0x6c => X11ByteOrder::LittleEndian,
        _ => return false,
    };
    // Byte 1 is unused padding (should be 0)
    // Bytes 2-3: major version (should be 11)
    // Bytes 4-5: minor version (should be 0)
    let major = match byte_order {
        X11ByteOrder::BigEndian => u16::from_be_bytes([input[2], input[3]]),
        X11ByteOrder::LittleEndian => u16::from_le_bytes([input[2], input[3]]),
    };
    let minor = match byte_order {
        X11ByteOrder::BigEndian => u16::from_be_bytes([input[4], input[5]]),
        X11ByteOrder::LittleEndian => u16::from_le_bytes([input[4], input[5]]),
    };
    major == 11 && minor == 0
}

/// Parse X11 Connection Setup Request (client → server).
///
/// Format:
///   byte-order (1) | unused (1) | major-version (2) | minor-version (2)
///   | auth-name-len (2) | auth-data-len (2) | unused (2)
///   | auth-name (padded to 4) | auth-data (padded to 4)
pub fn parse_setup_request(input: &[u8]) -> IResult<&[u8], X11SetupRequest> {
    // Fixed header: 12 bytes
    if input.len() < 12 {
        return Err(nom::Err::Incomplete(nom::Needed::new(12 - input.len())));
    }

    let byte_order = match input[0] {
        0x42 => X11ByteOrder::BigEndian,
        0x6c => X11ByteOrder::LittleEndian,
        _ => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag))),
    };

    let remaining = &input[2..]; // skip byte_order + unused
    let (remaining, major_version) = byte_order.read_u16(remaining)?;
    let (remaining, minor_version) = byte_order.read_u16(remaining)?;
    let (remaining, auth_name_len) = byte_order.read_u16(remaining)?;
    let (remaining, auth_data_len) = byte_order.read_u16(remaining)?;
    let remaining = &remaining[2..]; // skip unused 2 bytes

    let auth_name_padded = auth_name_len as usize + pad4(auth_name_len as usize);
    let auth_data_padded = auth_data_len as usize + pad4(auth_data_len as usize);
    let total_var = auth_name_padded + auth_data_padded;

    if remaining.len() < total_var {
        return Err(nom::Err::Incomplete(nom::Needed::new(total_var - remaining.len())));
    }

    let auth_protocol_name = if auth_name_len > 0 {
        String::from_utf8_lossy(&remaining[..auth_name_len as usize]).to_string()
    } else {
        String::new()
    };

    let remaining = &remaining[total_var..];

    Ok((remaining, X11SetupRequest {
        byte_order,
        major_version,
        minor_version,
        auth_protocol_name,
        auth_data_len,
    }))
}

/// Parse X11 Connection Setup Response (server → client).
///
/// Format:
///   status (1) | reason-len/unused (1) | major-version (2) | minor-version (2)
///   | additional-data-len (2) | ... (status-dependent)
///
/// Status: 0=Failed, 1=Success, 2=Authenticate
pub fn parse_setup_response(input: &[u8], byte_order: X11ByteOrder) -> IResult<&[u8], X11SetupResponse> {
    if input.len() < 8 {
        return Err(nom::Err::Incomplete(nom::Needed::new(8 - input.len())));
    }

    let status = input[0];
    let reason_len_or_unused = input[1];
    let remaining = &input[2..];
    let (remaining, major_version) = byte_order.read_u16(remaining)?;
    let (remaining, minor_version) = byte_order.read_u16(remaining)?;
    let (remaining, additional_data_len) = byte_order.read_u16(remaining)?;

    let additional_bytes = additional_data_len as usize * 4;
    if remaining.len() < additional_bytes {
        return Err(nom::Err::Incomplete(nom::Needed::new(additional_bytes - remaining.len())));
    }

    let result = match status {
        0 => {
            // Failed: reason string follows
            let reason_len = reason_len_or_unused as usize;
            let reason = if reason_len > 0 && remaining.len() >= reason_len {
                String::from_utf8_lossy(&remaining[..reason_len]).to_string()
            } else {
                String::new()
            };
            X11SetupResponse::Failed {
                major_version,
                minor_version,
                reason,
            }
        }
        1 => {
            // Success: parse additional data
            // Fixed fields: release(4) + rid_base(4) + rid_mask(4) + motion(4) +
            //   vendor_len(2) + max_req(2) + screens(1) + formats(1) +
            //   img_byte_order(1) + bmp_bit_order(1) + scanline_unit(1) + scanline_pad(1) +
            //   min_keycode(1) + max_keycode(1) + unused(4) = 32 bytes
            let data = remaining;
            if data.len() < 32 {
                return Err(nom::Err::Incomplete(nom::Needed::new(32 - data.len())));
            }
            let (d, release_number) = byte_order.read_u32(data)?;
            let (d, _resource_id_base) = byte_order.read_u32(d)?;
            let (d, _resource_id_mask) = byte_order.read_u32(d)?;
            let (d, _motion_buffer_size) = byte_order.read_u32(d)?;
            let (d, vendor_len) = byte_order.read_u16(d)?;
            let (d, _max_request_len) = byte_order.read_u16(d)?;
            let screen_count = d[0];
            let _format_count = d[1];
            // Skip: image-byte-order(1) + bitmap-format-bit-order(1) +
            //   scanline-unit(1) + scanline-pad(1) + min-keycode(1) + max-keycode(1) +
            //   unused(4) = 10 bytes after screen_count and format_count
            let d = &d[12..]; // 2 (screen+format) + 6 (byte fields) + 4 (unused) = 12

            let vendor = if vendor_len > 0 && d.len() >= vendor_len as usize {
                String::from_utf8_lossy(&d[..vendor_len as usize]).to_string()
            } else {
                String::new()
            };

            X11SetupResponse::Success {
                major_version,
                minor_version,
                release_number,
                vendor,
                screen_count,
            }
        }
        2 => {
            // Authenticate: reason string follows
            let reason = if additional_bytes > 0 && remaining.len() >= additional_bytes {
                String::from_utf8_lossy(&remaining[..additional_bytes]).to_string()
            } else {
                String::new()
            };
            X11SetupResponse::Authenticate { reason }
        }
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
    };

    let remaining = &remaining[additional_bytes..];
    Ok((remaining, result))
}

/// Parse X11 request header (Connected state, client → server).
///
/// Format: opcode (1) | data (1) | length (2)
/// Length is in 4-byte units, including the header.
pub fn parse_request_header(input: &[u8], byte_order: X11ByteOrder) -> IResult<&[u8], X11RequestHeader> {
    if input.len() < 4 {
        return Err(nom::Err::Incomplete(nom::Needed::new(4 - input.len())));
    }
    let opcode = input[0];
    let data = input[1];
    let (_, length) = byte_order.read_u16(&input[2..])?;

    // Validate: length must be at least 1 (header itself)
    if length == 0 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    let total_bytes = length as usize * 4;
    if input.len() < total_bytes {
        return Err(nom::Err::Incomplete(nom::Needed::new(total_bytes - input.len())));
    }

    Ok((&input[total_bytes..], X11RequestHeader { opcode, data, length }))
}

/// Parse X11 server message (Connected state, server → client).
///
/// Message type determined by first byte:
///   0 = Error (always 32 bytes)
///   1 = Reply (32 + length*4 bytes)
///   2-34 = Event (always 32 bytes)
pub fn parse_server_message(input: &[u8], byte_order: X11ByteOrder) -> IResult<&[u8], X11ServerMessage> {
    if input.len() < 32 {
        return Err(nom::Err::Incomplete(nom::Needed::new(32 - input.len())));
    }

    let msg_type = input[0];

    match msg_type {
        0 => {
            // Error: 32 bytes fixed
            let code = input[1];
            let (_, sequence) = byte_order.read_u16(&input[2..])?;
            // bytes 4-7: bad value (u32)
            // bytes 8-9: minor opcode
            let major_opcode = input[10];
            // remaining bytes are padding
            Ok((&input[32..], X11ServerMessage::Error {
                code,
                sequence,
                major_opcode,
            }))
        }
        1 => {
            // Reply: 32 bytes header + length*4 additional bytes
            let (_, sequence) = byte_order.read_u16(&input[2..])?;
            let (_, length) = byte_order.read_u32(&input[4..])?;
            let total = 32 + length as usize * 4;
            if input.len() < total {
                return Err(nom::Err::Incomplete(nom::Needed::new(total - input.len())));
            }
            Ok((&input[total..], X11ServerMessage::Reply { sequence, length }))
        }
        2..=34 => {
            // Event: 32 bytes fixed
            let code = input[0] & 0x7f; // clear SendEvent bit
            let (_, sequence) = byte_order.read_u16(&input[2..])?;
            Ok((&input[32..], X11ServerMessage::Event { code, sequence }))
        }
        _ => {
            // GenericEvent (35) or unknown: treat as event for robustness
            let code = input[0] & 0x7f;
            let (_, sequence) = byte_order.read_u16(&input[2..])?;
            // For GenericEvent (type 35), additional length is at bytes 4-7
            if msg_type == 35 {
                let (_, length) = byte_order.read_u32(&input[4..])?;
                let total = 32 + length as usize * 4;
                if input.len() < total {
                    return Err(nom::Err::Incomplete(nom::Needed::new(total - input.len())));
                }
                Ok((&input[total..], X11ServerMessage::Event { code, sequence }))
            } else {
                Ok((&input[32..], X11ServerMessage::Event { code, sequence }))
            }
        }
    }
}

/// Map X11 core protocol opcode (1-127) to name.
pub fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        1 => "CreateWindow",
        2 => "ChangeWindowAttributes",
        3 => "GetWindowAttributes",
        4 => "DestroyWindow",
        5 => "DestroySubwindows",
        6 => "ChangeSaveSet",
        7 => "ReparentWindow",
        8 => "MapWindow",
        9 => "MapSubwindows",
        10 => "UnmapWindow",
        11 => "UnmapSubwindows",
        12 => "ConfigureWindow",
        13 => "CirculateWindow",
        14 => "GetGeometry",
        15 => "QueryTree",
        16 => "InternAtom",
        17 => "GetAtomName",
        18 => "ChangeProperty",
        19 => "DeleteProperty",
        20 => "GetProperty",
        21 => "ListProperties",
        22 => "SetSelectionOwner",
        23 => "GetSelectionOwner",
        24 => "ConvertSelection",
        25 => "SendEvent",
        26 => "GrabPointer",
        27 => "UngrabPointer",
        28 => "GrabButton",
        29 => "UngrabButton",
        30 => "ChangeActivePointerGrab",
        31 => "GrabKeyboard",
        32 => "UngrabKeyboard",
        33 => "GrabKey",
        34 => "UngrabKey",
        35 => "AllowEvents",
        36 => "GrabServer",
        37 => "UngrabServer",
        38 => "QueryPointer",
        39 => "GetMotionEvents",
        40 => "TranslateCoordinates",
        41 => "WarpPointer",
        42 => "SetInputFocus",
        43 => "GetInputFocus",
        44 => "QueryKeymap",
        45 => "OpenFont",
        46 => "CloseFont",
        47 => "QueryFont",
        48 => "QueryTextExtents",
        49 => "ListFonts",
        50 => "ListFontsWithInfo",
        51 => "SetFontPath",
        52 => "GetFontPath",
        53 => "CreatePixmap",
        54 => "FreePixmap",
        55 => "CreateGC",
        56 => "ChangeGC",
        57 => "CopyGC",
        58 => "SetDashes",
        59 => "SetClipRectangles",
        60 => "FreeGC",
        61 => "ClearArea",
        62 => "CopyArea",
        63 => "CopyPlane",
        64 => "PolyPoint",
        65 => "PolyLine",
        66 => "PolySegment",
        67 => "PolyRectangle",
        68 => "PolyArc",
        69 => "FillPoly",
        70 => "PolyFillRectangle",
        71 => "PolyFillArc",
        72 => "PutImage",
        73 => "GetImage",
        74 => "PolyText8",
        75 => "PolyText16",
        76 => "ImageText8",
        77 => "ImageText16",
        78 => "CreateColormap",
        79 => "FreeColormap",
        80 => "CopyColormapAndFree",
        81 => "InstallColormap",
        82 => "UninstallColormap",
        83 => "ListInstalledColormaps",
        84 => "AllocColor",
        85 => "AllocNamedColor",
        86 => "AllocColorCells",
        87 => "AllocColorPlanes",
        88 => "FreeColors",
        89 => "StoreColors",
        90 => "StoreNamedColor",
        91 => "QueryColors",
        92 => "LookupColor",
        93 => "CreateCursor",
        94 => "CreateGlyphCursor",
        95 => "FreeCursor",
        96 => "RecolorCursor",
        97 => "QueryBestSize",
        98 => "QueryExtension",
        99 => "ListExtensions",
        100 => "ChangeKeyboardMapping",
        101 => "GetKeyboardMapping",
        102 => "ChangeKeyboardControl",
        103 => "GetKeyboardControl",
        104 => "Bell",
        105 => "ChangePointerControl",
        106 => "GetPointerControl",
        107 => "SetScreenSaver",
        108 => "GetScreenSaver",
        109 => "ChangeHosts",
        110 => "ListHosts",
        111 => "SetAccessControl",
        112 => "SetCloseDownMode",
        113 => "KillClient",
        114 => "RotateProperties",
        115 => "ForceScreenSaver",
        116 => "SetPointerMapping",
        117 => "GetPointerMapping",
        118 => "SetModifierMapping",
        119 => "GetModifierMapping",
        120 => "NoOperation",
        _ => "Unknown",
    }
}

/// Map X11 error code to name.
pub fn error_code_name(code: u8) -> &'static str {
    match code {
        1 => "BadRequest",
        2 => "BadValue",
        3 => "BadWindow",
        4 => "BadPixmap",
        5 => "BadAtom",
        6 => "BadCursor",
        7 => "BadFont",
        8 => "BadMatch",
        9 => "BadDrawable",
        10 => "BadAccess",
        11 => "BadAlloc",
        12 => "BadColor",
        13 => "BadGC",
        14 => "BadIDChoice",
        15 => "BadName",
        16 => "BadLength",
        17 => "BadImplementation",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_x11_valid_big_endian() {
        // Big-endian setup request: 'B', unused, major=11, minor=0
        let input = [
            0x42, 0x00, 0x00, 0x0B, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(probe_x11(&input));
    }

    #[test]
    fn test_probe_x11_valid_little_endian() {
        // Little-endian setup request: 'l', unused, major=11(LE), minor=0(LE)
        let input = [
            0x6c, 0x00, 0x0B, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(probe_x11(&input));
    }

    #[test]
    fn test_probe_x11_invalid() {
        // Invalid byte order
        let input = [
            0x41, 0x00, 0x00, 0x0B, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!probe_x11(&input));

        // Wrong version
        let input = [
            0x42, 0x00, 0x00, 0x0A, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!probe_x11(&input));

        // Too short
        let input = [0x42, 0x00, 0x00];
        assert!(!probe_x11(&input));
    }

    #[test]
    fn test_parse_setup_request_big_endian() {
        // Big-endian, version 11.0, no auth
        let input = [
            0x42, 0x00, // byte_order='B', unused
            0x00, 0x0B, // major=11 (BE)
            0x00, 0x00, // minor=0 (BE)
            0x00, 0x00, // auth_name_len=0
            0x00, 0x00, // auth_data_len=0
            0x00, 0x00, // unused
        ];
        let (rem, req) = parse_setup_request(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(req.byte_order, X11ByteOrder::BigEndian);
        assert_eq!(req.major_version, 11);
        assert_eq!(req.minor_version, 0);
        assert_eq!(req.auth_protocol_name, "");
        assert_eq!(req.auth_data_len, 0);
    }

    #[test]
    fn test_parse_setup_request_little_endian() {
        // Little-endian, version 11.0, with auth name "MIT-MAGIC-COOKIE-1"
        let auth_name = b"MIT-MAGIC-COOKIE-1";
        let auth_name_len = auth_name.len() as u16; // 18
        let auth_name_pad = pad4(auth_name_len as usize); // 2
        let mut input = vec![
            0x6c, 0x00, // byte_order='l', unused
        ];
        input.extend_from_slice(&11u16.to_le_bytes()); // major=11
        input.extend_from_slice(&0u16.to_le_bytes());  // minor=0
        input.extend_from_slice(&auth_name_len.to_le_bytes()); // auth_name_len=18
        input.extend_from_slice(&16u16.to_le_bytes()); // auth_data_len=16
        input.extend_from_slice(&[0x00, 0x00]); // unused
        input.extend_from_slice(auth_name);
        input.extend_from_slice(&vec![0u8; auth_name_pad]); // padding
        input.extend_from_slice(&[0u8; 16]); // auth data (16 bytes, no padding needed)

        let (rem, req) = parse_setup_request(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(req.byte_order, X11ByteOrder::LittleEndian);
        assert_eq!(req.major_version, 11);
        assert_eq!(req.minor_version, 0);
        assert_eq!(req.auth_protocol_name, "MIT-MAGIC-COOKIE-1");
        assert_eq!(req.auth_data_len, 16);
    }

    #[test]
    fn test_parse_setup_response_success() {
        let byte_order = X11ByteOrder::LittleEndian;
        // Build a minimal success response
        let vendor = b"TestVendor"; // 10 bytes
        let vendor_len = vendor.len() as u16;
        let vendor_pad = pad4(vendor_len as usize); // 2

        // Additional data: 32 bytes fixed + vendor + padding
        // (no pixmap formats or screens for simplicity)
        let additional_words = (32 + vendor_len as usize + vendor_pad) / 4;

        let mut input = vec![
            1,    // status = Success
            0,    // unused
        ];
        input.extend_from_slice(&11u16.to_le_bytes()); // major
        input.extend_from_slice(&0u16.to_le_bytes());  // minor
        input.extend_from_slice(&(additional_words as u16).to_le_bytes());

        // Additional data (32 bytes fixed part):
        input.extend_from_slice(&12101004u32.to_le_bytes()); // release_number
        input.extend_from_slice(&0u32.to_le_bytes());        // resource_id_base
        input.extend_from_slice(&0x001FFFFFu32.to_le_bytes()); // resource_id_mask
        input.extend_from_slice(&256u32.to_le_bytes());       // motion_buffer_size
        input.extend_from_slice(&vendor_len.to_le_bytes());   // vendor_len
        input.extend_from_slice(&65535u16.to_le_bytes());     // max_request_len
        input.push(1);  // screen_count
        input.push(0);  // format_count
        input.push(0);  // image_byte_order
        input.push(0);  // bitmap_format_bit_order
        input.push(32); // bitmap_format_scanline_unit
        input.push(32); // bitmap_format_scanline_pad
        input.push(8);  // min_keycode
        input.push(255);// max_keycode

        // unused(4) to complete the 32-byte fixed part
        input.extend_from_slice(&[0u8; 4]);

        // Vendor string + padding
        input.extend_from_slice(vendor);
        input.extend_from_slice(&vec![0u8; vendor_pad]);

        let (rem, resp) = parse_setup_response(&input, byte_order).unwrap();
        assert!(rem.is_empty());
        match resp {
            X11SetupResponse::Success {
                major_version,
                minor_version,
                release_number,
                vendor: v,
                screen_count,
            } => {
                assert_eq!(major_version, 11);
                assert_eq!(minor_version, 0);
                assert_eq!(release_number, 12101004);
                assert_eq!(v, "TestVendor");
                assert_eq!(screen_count, 1);
            }
            _ => panic!("Expected Success response"),
        }
    }

    #[test]
    fn test_parse_setup_response_failed() {
        let byte_order = X11ByteOrder::BigEndian;
        let reason = b"No auth";
        let reason_len = reason.len() as u8; // 7
        let reason_pad = pad4(reason_len as usize); // 1
        let additional_words = (reason_len as usize + reason_pad) / 4; // 2

        let mut input = vec![
            0,           // status = Failed
            reason_len,  // reason length
        ];
        input.extend_from_slice(&11u16.to_be_bytes()); // major
        input.extend_from_slice(&0u16.to_be_bytes());  // minor
        input.extend_from_slice(&(additional_words as u16).to_be_bytes());
        input.extend_from_slice(reason);
        input.extend_from_slice(&vec![0u8; reason_pad]);

        let (rem, resp) = parse_setup_response(&input, byte_order).unwrap();
        assert!(rem.is_empty());
        match resp {
            X11SetupResponse::Failed {
                major_version,
                minor_version,
                reason: r,
            } => {
                assert_eq!(major_version, 11);
                assert_eq!(minor_version, 0);
                assert_eq!(r, "No auth");
            }
            _ => panic!("Expected Failed response"),
        }
    }

    #[test]
    fn test_parse_setup_request_incomplete() {
        // Only 6 bytes, need 12
        let input = [0x42, 0x00, 0x00, 0x0B, 0x00, 0x00];
        let result = parse_setup_request(&input);
        assert!(matches!(result, Err(nom::Err::Incomplete(_))));
    }

    #[test]
    fn test_pad4() {
        assert_eq!(pad4(0), 0);
        assert_eq!(pad4(1), 3);
        assert_eq!(pad4(2), 2);
        assert_eq!(pad4(3), 1);
        assert_eq!(pad4(4), 0);
        assert_eq!(pad4(5), 3);
        assert_eq!(pad4(18), 2);
    }

    #[test]
    fn test_parse_request_header_little_endian() {
        let byte_order = X11ByteOrder::LittleEndian;
        // CreateWindow (opcode=1), length=8 (32 bytes)
        let mut input = vec![1u8, 0x00]; // opcode=1, data=0
        input.extend_from_slice(&8u16.to_le_bytes()); // length=8 (32 bytes)
        input.extend_from_slice(&[0u8; 28]); // remaining 28 bytes of request body

        let (rem, hdr) = parse_request_header(&input, byte_order).unwrap();
        assert!(rem.is_empty());
        assert_eq!(hdr.opcode, 1);
        assert_eq!(hdr.length, 8);
    }

    #[test]
    fn test_parse_request_header_big_endian() {
        let byte_order = X11ByteOrder::BigEndian;
        // MapWindow (opcode=8), length=2 (8 bytes)
        let mut input = vec![8u8, 0x00]; // opcode=8, data=0
        input.extend_from_slice(&2u16.to_be_bytes()); // length=2 (8 bytes)
        input.extend_from_slice(&[0u8; 4]); // remaining 4 bytes

        let (rem, hdr) = parse_request_header(&input, byte_order).unwrap();
        assert!(rem.is_empty());
        assert_eq!(hdr.opcode, 8);
        assert_eq!(hdr.length, 2);
    }

    #[test]
    fn test_parse_server_reply() {
        let byte_order = X11ByteOrder::LittleEndian;
        let mut input = vec![1u8, 0x00]; // type=Reply, unused
        input.extend_from_slice(&1u16.to_le_bytes()); // sequence=1
        input.extend_from_slice(&2u32.to_le_bytes()); // length=2 (8 additional bytes)
        input.extend_from_slice(&[0u8; 24]); // remaining 24 bytes of base reply
        input.extend_from_slice(&[0u8; 8]);  // 2*4 = 8 additional bytes

        let (rem, msg) = parse_server_message(&input, byte_order).unwrap();
        assert!(rem.is_empty());
        match msg {
            X11ServerMessage::Reply { sequence, length } => {
                assert_eq!(sequence, 1);
                assert_eq!(length, 2);
            }
            _ => panic!("Expected Reply"),
        }
    }

    #[test]
    fn test_parse_server_error() {
        let byte_order = X11ByteOrder::LittleEndian;
        let mut input = vec![0u8, 8u8]; // type=Error, code=BadMatch(8)
        input.extend_from_slice(&5u16.to_le_bytes()); // sequence=5
        input.extend_from_slice(&[0u8; 4]); // bad value
        input.extend_from_slice(&[0u8; 2]); // minor opcode
        input.push(62); // major_opcode = CopyArea
        input.extend_from_slice(&[0u8; 21]); // padding to reach 32

        let (rem, msg) = parse_server_message(&input, byte_order).unwrap();
        assert!(rem.is_empty());
        match msg {
            X11ServerMessage::Error { code, sequence, major_opcode } => {
                assert_eq!(code, 8);
                assert_eq!(sequence, 5);
                assert_eq!(major_opcode, 62);
            }
            _ => panic!("Expected Error"),
        }
    }

    #[test]
    fn test_parse_server_event() {
        let byte_order = X11ByteOrder::LittleEndian;
        let mut input = vec![2u8, 0u8]; // type=KeyPress(2), detail
        input.extend_from_slice(&10u16.to_le_bytes()); // sequence=10
        input.extend_from_slice(&[0u8; 28]); // remaining bytes to reach 32

        let (rem, msg) = parse_server_message(&input, byte_order).unwrap();
        assert!(rem.is_empty());
        match msg {
            X11ServerMessage::Event { code, sequence } => {
                assert_eq!(code, 2);
                assert_eq!(sequence, 10);
            }
            _ => panic!("Expected Event"),
        }
    }

    #[test]
    fn test_opcode_name_mapping() {
        assert_eq!(opcode_name(1), "CreateWindow");
        assert_eq!(opcode_name(8), "MapWindow");
        assert_eq!(opcode_name(16), "InternAtom");
        assert_eq!(opcode_name(45), "OpenFont");
        assert_eq!(opcode_name(55), "CreateGC");
        assert_eq!(opcode_name(72), "PutImage");
        assert_eq!(opcode_name(98), "QueryExtension");
        assert_eq!(opcode_name(120), "NoOperation");
        assert_eq!(opcode_name(200), "Unknown");
    }

    #[test]
    fn test_error_code_name_mapping() {
        assert_eq!(error_code_name(1), "BadRequest");
        assert_eq!(error_code_name(3), "BadWindow");
        assert_eq!(error_code_name(8), "BadMatch");
        assert_eq!(error_code_name(17), "BadImplementation");
        assert_eq!(error_code_name(100), "Unknown");
    }
}
