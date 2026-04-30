use nom7::bytes::complete::{take, take_till};
use nom7::number::complete::le_u24;
use nom7::number::complete::u8 as parse_u8;
use nom7::IResult;

/// MySQL 包头：3字节小端长度 + 1字节序列号
#[derive(Debug, PartialEq)]
pub struct MysqlHeader {
    pub payload_length: u32,
    pub sequence_id: u8,
}

/// MySQL Initial Handshake Packet (v10) 核心字段
#[derive(Debug, PartialEq)]
pub struct MysqlGreeting {
    pub header: MysqlHeader,
    pub protocol_version: u8,
    pub server_version: String,
}

pub fn parse_mysql_header(input: &[u8]) -> IResult<&[u8], MysqlHeader> {
    let (input, payload_length) = le_u24(input)?;
    let (input, sequence_id) = parse_u8(input)?;
    Ok((
        input,
        MysqlHeader {
            payload_length,
            sequence_id,
        },
    ))
}

/// 解析 NUL 终止的字符串，消耗掉末尾的 \x00
fn parse_nul_string(input: &[u8]) -> IResult<&[u8], String> {
    let (input, bytes) = take_till(|b| b == 0x00)(input)?;
    let (input, _nul) = take(1u8)(input)?; // skip \x00
    Ok((input, String::from_utf8_lossy(bytes).to_string()))
}

/// 解析 MySQL Initial Handshake Packet，提取协议版本和服务器版本字符串
pub fn parse_mysql_greeting(input: &[u8]) -> IResult<&[u8], MysqlGreeting> {
    let (input, header) = parse_mysql_header(input)?;
    let (input, protocol_version) = parse_u8(input)?;
    let (input, server_version) = parse_nul_string(input)?;
    Ok((
        input,
        MysqlGreeting {
            header,
            protocol_version,
            server_version,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mysql_header() {
        let data: &[u8] = &[0x4a, 0x00, 0x00, 0x00];
        let (rem, header) = parse_mysql_header(data).unwrap();
        assert_eq!(header.payload_length, 74);
        assert_eq!(header.sequence_id, 0);
        assert!(rem.is_empty());
    }

    #[test]
    fn test_parse_mysql_header_incomplete() {
        let data: &[u8] = &[0x4a, 0x00];
        assert!(parse_mysql_header(data).is_err());
    }

    #[test]
    fn test_parse_nul_string() {
        let data: &[u8] = b"8.0.32\x00rest";
        let (rem, s) = parse_nul_string(data).unwrap();
        assert_eq!(s, "8.0.32");
        assert_eq!(rem, b"rest");
    }

    #[test]
    fn test_parse_mysql_greeting_real_packet() {
        // 真实 MySQL 8.0.32 握手包（截取到 server_version 之后）
        // 包头: payload_length=14, seq=0
        // payload: protocol=0x0a, version="8.0.32\x00", 后面跟一些剩余数据
        #[rustfmt::skip]
        let data: &[u8] = &[
            // -- header --
            0x0e, 0x00, 0x00,  // payload_length = 14 (小端)
            0x00,              // sequence_id = 0
            // -- payload --
            0x0a,              // protocol_version = 10
            // server_version = "8.0.32"
            0x38, 0x2e, 0x30, 0x2e, 0x33, 0x32, 0x00,
            // 剩余数据 (thread_id 等，本次不解析)
            0x08, 0x00, 0x00, 0x00, 0xab, 0xcd,
        ];
        let (rem, greeting) = parse_mysql_greeting(data).unwrap();
        assert_eq!(greeting.header.payload_length, 14);
        assert_eq!(greeting.header.sequence_id, 0);
        assert_eq!(greeting.protocol_version, 10);
        assert_eq!(greeting.server_version, "8.0.32");
        // 剩余数据应为 thread_id 等后续字段
        assert_eq!(rem.len(), 6);
    }

    #[test]
    fn test_parse_mysql_greeting_with_suffix() {
        // 版本字符串带 Linux 发行版后缀
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x1e, 0x00, 0x00, 0x00,  // header: len=30, seq=0
            0x0a,                     // protocol_version = 10
            // "5.7.38-0ubuntu0.22.04.1\x00"
            0x35, 0x2e, 0x37, 0x2e, 0x33, 0x38, 0x2d,
            0x30, 0x75, 0x62, 0x75, 0x6e, 0x74, 0x75,
            0x30, 0x2e, 0x32, 0x32, 0x2e, 0x30, 0x34,
            0x2e, 0x31, 0x00,
            // 一些剩余数据
            0x01, 0x02,
        ];
        let (rem, greeting) = parse_mysql_greeting(data).unwrap();
        assert_eq!(greeting.protocol_version, 10);
        assert_eq!(greeting.server_version, "5.7.38-0ubuntu0.22.04.1");
        assert_eq!(rem.len(), 2);
    }

    #[test]
    fn test_parse_mysql_greeting_pcap_capture() {
        // 来自 pcap/mysql_complete.pcap 的真实握手包 (MySQL 5.0.54)
        // tshark 提取的 tcp.payload (server→client 第一个包)
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x34, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x30,
            0x2e, 0x35, 0x34, 0x00, 0x5e, 0x00, 0x00, 0x00,
            0x3e, 0x7e, 0x24, 0x34, 0x75, 0x74, 0x68, 0x2c,
            0x00, 0x2c, 0xa2, 0x21, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x3e, 0x36, 0x31, 0x32, 0x49,
            0x57, 0x5a, 0x3e, 0x66, 0x68, 0x57, 0x58, 0x00,
        ];
        let (rem, greeting) = parse_mysql_greeting(data).unwrap();
        assert_eq!(greeting.header.payload_length, 0x34); // 52
        assert_eq!(greeting.header.sequence_id, 0);
        assert_eq!(greeting.protocol_version, 10);
        assert_eq!(greeting.server_version, "5.0.54");
        // 剩余数据 = payload - 1(proto) - 7(version+NUL) = 52 - 8 = 44
        assert_eq!(rem.len(), 44);
    }
}
