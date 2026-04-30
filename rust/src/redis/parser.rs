use nom7::branch::alt;
use nom7::bytes::streaming::{tag, take, take_while};
use nom7::character::streaming::crlf;
use nom7::IResult;

#[derive(Debug, Clone, PartialEq)]
pub enum RespValue {
    SimpleString(Vec<u8>),
    Error(Vec<u8>),
    Integer(i64),
    BulkString(Vec<u8>),
    Array(Vec<RespValue>),
    Null,
}

fn is_not_cr(b: u8) -> bool {
    b != b'\r'
}

fn parse_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, line) = take_while(is_not_cr)(input)?;
    let (input, _) = crlf(input)?;
    Ok((input, line))
}

fn parse_simple_string(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = tag(b"+")(input)?;
    let (input, line) = parse_line(input)?;
    Ok((input, RespValue::SimpleString(line.to_vec())))
}

fn parse_error(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = tag(b"-")(input)?;
    let (input, line) = parse_line(input)?;
    Ok((input, RespValue::Error(line.to_vec())))
}

fn parse_integer(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = tag(b":")(input)?;
    let (input, line) = parse_line(input)?;
    let s = std::str::from_utf8(line).map_err(|_| {
        nom7::Err::Error(nom7::error::Error::new(input, nom7::error::ErrorKind::Digit))
    })?;
    let n: i64 = s.parse().map_err(|_| {
        nom7::Err::Error(nom7::error::Error::new(input, nom7::error::ErrorKind::Digit))
    })?;
    Ok((input, RespValue::Integer(n)))
}

fn parse_length(input: &[u8]) -> IResult<&[u8], i64> {
    let (input, line) = parse_line(input)?;
    let s = std::str::from_utf8(line).map_err(|_| {
        nom7::Err::Error(nom7::error::Error::new(input, nom7::error::ErrorKind::Digit))
    })?;
    let n: i64 = s.parse().map_err(|_| {
        nom7::Err::Error(nom7::error::Error::new(input, nom7::error::ErrorKind::Digit))
    })?;
    Ok((input, n))
}

fn parse_bulk_string(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = tag(b"$")(input)?;
    let (input, len) = parse_length(input)?;
    if len < 0 {
        return Ok((input, RespValue::Null));
    }
    let (input, data) = take(len as usize)(input)?;
    let (input, _) = crlf(input)?;
    Ok((input, RespValue::BulkString(data.to_vec())))
}

fn parse_array(input: &[u8]) -> IResult<&[u8], RespValue> {
    let (input, _) = tag(b"*")(input)?;
    let (input, count) = parse_length(input)?;
    if count < 0 {
        return Ok((input, RespValue::Null));
    }
    let mut input = input;
    let mut items = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (rem, val) = parse_resp_value(input)?;
        items.push(val);
        input = rem;
    }
    Ok((input, RespValue::Array(items)))
}

pub fn parse_resp_value(input: &[u8]) -> IResult<&[u8], RespValue> {
    alt((
        parse_simple_string,
        parse_error,
        parse_integer,
        parse_bulk_string,
        parse_array,
    ))(input)
}

/// Extract software name and version from HELLO response array.
/// HELLO response is a flat array with alternating key/value pairs.
pub fn extract_hello_version(items: &[RespValue]) -> Option<(String, String)> {
    let mut server_name: Option<String> = None;
    let mut version: Option<String> = None;

    let mut i = 0;
    while i + 1 < items.len() {
        let key = match &items[i] {
            RespValue::BulkString(b) | RespValue::SimpleString(b) => {
                String::from_utf8_lossy(b).to_lowercase()
            }
            _ => {
                i += 2;
                continue;
            }
        };
        let val = match &items[i + 1] {
            RespValue::BulkString(b) | RespValue::SimpleString(b) => {
                String::from_utf8_lossy(b).to_string()
            }
            _ => String::new(),
        };
        match key.as_str() {
            "server" => server_name = Some(val),
            "version" => version = Some(val),
            _ => {}
        }
        i += 2;
    }

    match (server_name, version) {
        (Some(name), Some(ver)) => Some((name, ver)),
        (None, Some(ver)) => Some(("redis".to_string(), ver)),
        _ => None,
    }
}

/// Extract version from INFO response bulk string.
/// Searches for `redis_version:X.Y.Z` line.
pub fn extract_info_version(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(ver) = line.strip_prefix("redis_version:") {
            let ver = ver.trim();
            if !ver.is_empty() {
                return Some(ver.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_string() {
        let input = b"+OK\r\n";
        let (rem, val) = parse_resp_value(input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(val, RespValue::SimpleString(b"OK".to_vec()));
    }

    #[test]
    fn test_parse_error() {
        let input = b"-ERR unknown\r\n";
        let (rem, val) = parse_resp_value(input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(val, RespValue::Error(b"ERR unknown".to_vec()));
    }

    #[test]
    fn test_parse_integer() {
        let input = b":1000\r\n";
        let (rem, val) = parse_resp_value(input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(val, RespValue::Integer(1000));
    }

    #[test]
    fn test_parse_negative_integer() {
        let input = b":-42\r\n";
        let (_, val) = parse_resp_value(input).unwrap();
        assert_eq!(val, RespValue::Integer(-42));
    }

    #[test]
    fn test_parse_bulk_string() {
        let input = b"$6\r\nfoobar\r\n";
        let (rem, val) = parse_resp_value(input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(val, RespValue::BulkString(b"foobar".to_vec()));
    }

    #[test]
    fn test_parse_null_bulk_string() {
        let input = b"$-1\r\n";
        let (rem, val) = parse_resp_value(input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(val, RespValue::Null);
    }

    #[test]
    fn test_parse_array() {
        let input = b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
        let (rem, val) = parse_resp_value(input).unwrap();
        assert!(rem.is_empty());
        match val {
            RespValue::Array(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], RespValue::BulkString(b"foo".to_vec()));
                assert_eq!(items[1], RespValue::BulkString(b"bar".to_vec()));
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn test_parse_empty_array() {
        let input = b"*0\r\n";
        let (_, val) = parse_resp_value(input).unwrap();
        assert_eq!(val, RespValue::Array(vec![]));
    }

    #[test]
    fn test_parse_incomplete() {
        let input = b"$6\r\nfoo";
        assert!(parse_resp_value(input).is_err());
    }

    #[test]
    fn test_extract_hello_version() {
        let items = vec![
            RespValue::BulkString(b"server".to_vec()),
            RespValue::BulkString(b"redis".to_vec()),
            RespValue::BulkString(b"version".to_vec()),
            RespValue::BulkString(b"7.2.4".to_vec()),
            RespValue::BulkString(b"proto".to_vec()),
            RespValue::Integer(3),
        ];
        let result = extract_hello_version(&items);
        assert_eq!(result, Some(("redis".to_string(), "7.2.4".to_string())));
    }

    #[test]
    fn test_extract_hello_version_no_server_key() {
        let items = vec![
            RespValue::BulkString(b"version".to_vec()),
            RespValue::BulkString(b"6.0.0".to_vec()),
        ];
        let result = extract_hello_version(&items);
        assert_eq!(result, Some(("redis".to_string(), "6.0.0".to_string())));
    }

    #[test]
    fn test_extract_hello_version_missing() {
        let items = vec![
            RespValue::BulkString(b"server".to_vec()),
            RespValue::BulkString(b"redis".to_vec()),
        ];
        let result = extract_hello_version(&items);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_info_version() {
        let data = b"# Server\r\nredis_version:6.2.14\r\nredis_git_sha1:00000000\r\n";
        let result = extract_info_version(data);
        assert_eq!(result, Some("6.2.14".to_string()));
    }

    #[test]
    fn test_extract_info_version_not_found() {
        let data = b"# Clients\r\nconnected_clients:1\r\n";
        assert_eq!(extract_info_version(data), None);
    }
}
