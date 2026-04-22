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

//! BER (Basic Encoding Rules) 基础编解码函数。
//!
//! 提供 ASN.1 BER TLV 解析、长度编码、整数解析、字符串解析等通用功能，
//! 供 MMS PDU 解析和 Session/Presentation 层解包复用。

/// BER 递归解析最大深度，防止恶意嵌套数据导致栈溢出。
pub(super) const MAX_BER_DEPTH: usize = 16;

/// Parse a BER TLV (Tag-Length-Value) header.
/// Returns (tag_byte, is_constructed, tag_number, content, remaining).
/// tag_number is u32 to support multi-byte tags (tag >= 31).
pub(super) fn parse_ber_tlv(input: &[u8]) -> Result<(u8, bool, u32, &[u8], &[u8]), ()> {
    if input.is_empty() {
        return Err(());
    }

    let tag_byte = input[0];
    let is_constructed = (tag_byte & 0x20) != 0; // bit 5 = constructed 标志
    let low5 = tag_byte & 0x1F; // 低 5 位：若全 1 则为多字节标签

    let (actual_tag, tag_header_len) = if low5 == 0x1F {
        // 多字节标签：后续字节使用 base-128 编码，最高位为延续标志
        let mut tag_val: u32 = 0;
        let mut idx = 1;
        loop {
            if idx >= input.len() {
                return Err(());
            }
            let b = input[idx];
            tag_val = (tag_val << 7) | ((b & 0x7F) as u32);
            idx += 1;
            if (b & 0x80) == 0 {
                break;
            }
            if idx > 5 {
                return Err(());
            }
        }
        (tag_val, idx)
    } else {
        (low5 as u32, 1)
    };

    let (length, header_len) = parse_ber_length(&input[tag_header_len..])?;
    let total_header = tag_header_len + header_len;

    if input.len() < total_header + length {
        return Err(());
    }

    let content = &input[total_header..total_header + length];
    let remaining = &input[total_header + length..];

    Ok((tag_byte, is_constructed, actual_tag, content, remaining))
}

/// 解析 BER 长度编码。
/// 返回 (长度值, 消耗的字节数)。
pub(super) fn parse_ber_length(input: &[u8]) -> Result<(usize, usize), ()> {
    if input.is_empty() {
        return Err(());
    }

    let first = input[0];
    if first < 0x80 {
        // 短格式：单字节直接表示长度 (0-127)
        Ok((first as usize, 1))
    } else if first == 0x80 {
        // 不定长格式，本实现不支持
        Err(())
    } else {
        // 长格式：低 7 位 = 后续长度字节数，再按大端拼接
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

/// Parse a BER INTEGER value (unsigned).
/// 用于 invokeId、objectClass 等协议定义为非负的字段。
pub(super) fn parse_ber_integer(content: &[u8]) -> Result<u32, ()> {
    if content.is_empty() || content.len() > 4 {
        return Err(());
    }
    let mut val: u32 = 0;
    for &b in content {
        val = (val << 8) | (b as u32);
    }
    Ok(val)
}

/// Parse a BER INTEGER value (signed).
/// 用于 MMS Data [5] integer 等 ASN.1 有符号整数字段。
/// 参照 libiec61850 BerDecoder_decodeInt32 的符号扩展逻辑。
pub(super) fn parse_ber_signed_integer(content: &[u8]) -> Result<i64, ()> {
    if content.is_empty() || content.len() > 8 {
        return Err(());
    }
    // 最高位为 1 时初始化为 -1（全 F），实现符号扩展
    let mut val: i64 = if (content[0] & 0x80) != 0 { -1 } else { 0 };
    for &b in content {
        val = (val << 8) | (b as i64);
    }
    Ok(val)
}

/// Parse a BER VisibleString/UTF8String value.
pub(super) fn parse_ber_string(content: &[u8]) -> String {
    String::from_utf8_lossy(content).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====== 从 mms_pdu.rs 搬入的原有测试 ======

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

    // ====== 新增 BER 边界测试 ======

    #[test]
    fn test_parse_ber_length_empty() {
        assert!(parse_ber_length(&[]).is_err());
    }

    #[test]
    fn test_parse_ber_length_indefinite() {
        // 不定长格式 (0x80) 不支持，应返回 Err
        assert!(parse_ber_length(&[0x80]).is_err());
    }

    #[test]
    fn test_parse_ber_integer_empty() {
        assert!(parse_ber_integer(&[]).is_err());
    }

    #[test]
    fn test_parse_ber_integer_overflow() {
        // 超过 4 字节应返回 Err
        assert!(parse_ber_integer(&[0x01, 0x02, 0x03, 0x04, 0x05]).is_err());
    }

    // ====== parse_ber_signed_integer 测试 ======

    #[test]
    fn test_parse_ber_signed_integer_positive() {
        assert_eq!(parse_ber_signed_integer(&[0x01]).unwrap(), 1);
        assert_eq!(parse_ber_signed_integer(&[0x7F]).unwrap(), 127);
        assert_eq!(parse_ber_signed_integer(&[0x00, 0xFF]).unwrap(), 255);
        assert_eq!(parse_ber_signed_integer(&[0x01, 0x00]).unwrap(), 256);
    }

    #[test]
    fn test_parse_ber_signed_integer_negative() {
        // -1: 单字节 0xFF
        assert_eq!(parse_ber_signed_integer(&[0xFF]).unwrap(), -1);
        // -1: 双字节 0xFF 0xFF
        assert_eq!(parse_ber_signed_integer(&[0xFF, 0xFF]).unwrap(), -1);
        // -128: 0x80
        assert_eq!(parse_ber_signed_integer(&[0x80]).unwrap(), -128);
        // -256: 0xFF 0x00
        assert_eq!(parse_ber_signed_integer(&[0xFF, 0x00]).unwrap(), -256);
        // -32768: 0x80 0x00
        assert_eq!(parse_ber_signed_integer(&[0x80, 0x00]).unwrap(), -32768);
    }

    #[test]
    fn test_parse_ber_signed_integer_zero() {
        assert_eq!(parse_ber_signed_integer(&[0x00]).unwrap(), 0);
    }

    #[test]
    fn test_parse_ber_signed_integer_empty() {
        assert!(parse_ber_signed_integer(&[]).is_err());
    }

    #[test]
    fn test_parse_ber_signed_integer_max_8_bytes() {
        // 8 字节正数
        assert!(parse_ber_signed_integer(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_ok());
        // 超过 8 字节应返回 Err
        assert!(parse_ber_signed_integer(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_parse_ber_tlv_empty() {
        assert!(parse_ber_tlv(&[]).is_err());
    }

    #[test]
    fn test_parse_ber_tlv_truncated() {
        // 标签声明长度 = 5，但实际只有 1 字节内容
        assert!(parse_ber_tlv(&[0x30, 0x05, 0x01]).is_err());
    }

    #[test]
    fn test_parse_ber_tlv_multibyte_tag() {
        // 多字节标签：tag_byte=0x1F (低5位全1) + 后续字节 0x20 (tag_number=32)
        // 长度 = 1，内容 = [0xAA]
        let data = [0x1F, 0x20, 0x01, 0xAA];
        let (tag_byte, is_constructed, tag_number, content, remaining) =
            parse_ber_tlv(&data).unwrap();
        assert_eq!(tag_byte, 0x1F);
        assert!(!is_constructed);
        assert_eq!(tag_number, 32);
        assert_eq!(content, &[0xAA]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_parse_ber_string_invalid_utf8() {
        // 非法 UTF-8 序列应容错处理（使用 replacement character）
        let invalid = [0xFF, 0xFE, 0x41]; // 无效 UTF-8 + 'A'
        let result = parse_ber_string(&invalid);
        assert!(result.contains('A'));
        assert!(result.contains('\u{FFFD}')); // replacement character
    }
}
