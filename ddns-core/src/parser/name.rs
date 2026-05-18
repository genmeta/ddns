use std::collections::HashMap;

use bytes::BufMut;
use nom::{IResult, bytes::streaming::take, number::streaming::be_u8};

pub type Name = String;

pub fn be_name<'a>(input: &'a [u8], origin: &'a [u8]) -> IResult<&'a [u8], Name> {
    be_name_inner(input, origin, &mut vec![])
}

/// RFC 1035 4.1.4 的压缩上下文：记录已写入消息中“某个 name 后缀”的偏移量。
///
/// key 为后缀域名（例如 `skype.com`），value 为其在消息起始处的偏移（14-bit）。
#[derive(Debug, Default)]
pub struct NameCompression {
    suffix_offsets: HashMap<String, u16>,
}

impl NameCompression {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_suffix_offset(&self, suffix: &str) -> Option<u16> {
        self.suffix_offsets.get(suffix).copied()
    }

    fn remember_suffix(&mut self, suffix: &str, offset: u16) {
        self.suffix_offsets
            .entry(suffix.to_string())
            .or_insert(offset);
    }
}

/// 按 RFC 1035 4.1.4 进行压缩编码（若命中已有后缀则写入 pointer 并终止 name）。
///
/// 该函数只会引用“已写入到当前消息 earlier 的位置”，并保证指针偏移不超过 14-bit。
pub fn put_name(buf: &mut Vec<u8>, name: &Name, ctx: &mut NameCompression) -> usize {
    let start_len = buf.len();

    if name == "." {
        buf.put_u8(0);
        return buf.len() - start_len;
    }

    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        buf.put_u8(0);
        return buf.len() - start_len;
    }

    let mut labels = Vec::new();
    let parts: Vec<&str> = trimmed.split('.').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            if i != parts.len() - 1 {
                tracing::warn!(target: "mdns", name, "invalid empty label in middle");
            }
            continue;
        }
        labels.push(*part);
    }

    if labels.is_empty() {
        buf.put_u8(0);
        return buf.len() - start_len;
    }

    let mut suffixes = Vec::with_capacity(labels.len());
    let mut current = String::new();
    for &label in labels.iter().rev() {
        if current.is_empty() {
            current = label.to_string();
        } else {
            current = format!("{label}.{current}");
        }
        suffixes.push(current.clone());
    }
    suffixes.reverse();

    for i in 0..labels.len() {
        let suffix = &suffixes[i];
        if let Some(offset) = ctx.get_suffix_offset(suffix) {
            let ptr = 0xC000u16 | (offset & 0x3FFF);
            buf.put_u16(ptr);
            return buf.len() - start_len;
        }

        if buf.len() <= 0x3FFF {
            let offset = buf.len() as u16;
            ctx.remember_suffix(suffix, offset);
        }

        let label = labels[i];
        let len = label.len();
        if len > 63 {
            tracing::warn!(target: "mdns", name, "label exceeds 63 bytes");
        }
        buf.put_u8(len as u8);
        buf.put_slice(label.as_bytes());
    }

    buf.put_u8(0);
    buf.len() - start_len
}

/// 解析一个 DNS name（RFC 1035 3.1 / 4.1.4）。
///
/// name 在消息中的编码是 “label 序列 + 0 终止符”，其中每个 label 的格式是：
/// - `len(1 byte)` + `label bytes(len bytes)`，`len` 取值范围 0..=63
/// - 当 `len == 0` 表示根标签（root），name 结束
///
/// RFC 1035 4.1.4 允许消息压缩：当长度字节的高 2-bit 为 `11`（即 `(len & 0xC0) == 0xC0`）
/// 时，这两个字节组成一个 14-bit 的偏移量，指向消息起始处的某个 name 后缀：
/// - `pointer = 0b11xxxxxx xxxxxxxx`，offset 为低 14-bit
/// - 指针一旦出现，当前 name 立即结束（后面不会再有 root `0`）
///
/// 解析时需要防止恶意数据构造 “指针环”，这里用 `visited` 记录递归访问过的 offset，
/// 遇到重复 offset 即报错。
fn be_name_inner<'a>(
    input: &'a [u8],
    origin: &'a [u8],
    visited: &mut Vec<usize>,
) -> IResult<&'a [u8], Name> {
    let (remain, labels) = be_name_labels(input, origin, visited)?;
    if labels.is_empty() {
        return Ok((remain, ".".to_string()));
    }
    Ok((remain, labels.join(".")))
}

fn be_name_labels<'a>(
    mut input: &'a [u8],
    origin: &'a [u8],
    visited: &mut Vec<usize>,
) -> IResult<&'a [u8], Vec<String>> {
    let mut labels = Vec::new();
    loop {
        let (remain, len) = be_u8(input)?;
        if len == 0 {
            return Ok((remain, labels));
        }

        if (len & 0xC0) == 0xC0 {
            let (remain, offset_byte) = be_u8(remain)?;
            let offset = (((len & 0x3F) as u16) << 8) | offset_byte as u16;
            let offset = offset as usize;
            if offset >= origin.len() || visited.contains(&offset) {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
            visited.push(offset);
            let (_, suffix) = be_name_labels(&origin[offset..], origin, visited)?;
            visited.pop();
            labels.extend(suffix);
            return Ok((remain, labels));
        }

        if len > 63 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }

        let (remain, label_bytes) = take(len)(remain)?;
        labels.push(String::from_utf8_lossy(label_bytes).into_owned());
        input = remain;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn gen_ascii_label_bytes(len: usize, state: &mut u64) -> Vec<u8> {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = (*state as usize) % ALPHABET.len();
            out.push(ALPHABET[idx]);
        }
        out
    }

    fn gen_ascii_wire_name(state: &mut u64) -> Vec<u8> {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let label_count = 1 + ((*state as usize) % 5);
        let mut out = Vec::new();
        for _ in 0..label_count {
            *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = 1 + ((*state as usize) % 20);
            out.push(len as u8);
            out.extend_from_slice(&gen_ascii_label_bytes(len, state));
        }
        out.push(0);
        out
    }

    #[test]
    fn parse_example_name() {
        let name = b"\x07example\x03com\x00";
        let (remain, parsed_name) = be_name(name, name).unwrap();
        assert_eq!(remain.len(), 0);
        assert_eq!(parsed_name, "example.com");
    }

    #[test]
    fn parse_badpointer_same_offset() {
        // A buffer where an offset points to itself,
        // which is a bad compression pointer.
        let same_offset = [192, 2, 192, 2];
        let ret = be_name(&same_offset, &same_offset);
        assert!(ret.is_err())
    }

    #[test]
    fn parse_badpointer_loop_between_offsets() {
        let buf = [0xC0, 0x02, 0xC0, 0x00];
        let ret = be_name(&buf, &buf);
        assert!(ret.is_err());
    }

    #[test]
    fn parse_badpointer_out_of_bounds() {
        let buf = [0xC0, 0x10, 0x00];
        let ret = be_name(&buf, &buf);
        assert!(ret.is_err());
    }

    #[test]
    fn parse_label_too_long_is_error() {
        let mut buf = Vec::new();
        buf.push(64);
        buf.extend(std::iter::repeat_n(b'a', 64));
        buf.push(0);
        let ret = be_name(&buf, &buf);
        assert!(ret.is_err());
    }

    #[test]
    fn parse_pointer_to_root() {
        let buf = b"\x00\xc0\x00";
        let (remain, parsed) = be_name(&buf[1..], buf).unwrap();
        assert!(remain.is_empty());
        assert_eq!(parsed, ".");
    }

    #[test]
    fn pointer_terminates_name_and_does_not_consume_trailing_bytes() {
        let buf = b"\x03com\x00\x03www\xc0\x00\x00";
        let (remain, parsed) = be_name(&buf[5..], buf).unwrap();
        assert_eq!(parsed, "www.com");
        assert_eq!(remain, b"\x00");
    }

    #[test]
    fn parse_chained_compression_pointers() {
        let buf = b"\x03com\x00\xc0\x00\x03www\xc0\x05";
        let (remain, parsed) = be_name(&buf[7..], buf).unwrap();
        assert!(remain.is_empty());
        assert_eq!(parsed, "www.com");
    }

    #[test]
    fn nested_names() {
        let buf = b"\x02xx\x00\x02yy\xc0\x00\x02zz\xc0\x04";

        let (remaining, parsed) = be_name(buf, buf).unwrap();
        assert_eq!(remaining.len(), 10);
        assert_eq!(parsed, "xx");

        let (_remaining, parsed) = be_name(&buf[4..], buf).unwrap();
        assert_eq!(parsed, "yy.xx");

        // offset only
        let (_remaining, parsed) = be_name(&buf[7..], buf).unwrap();
        assert_eq!(parsed, "xx");

        let (_remaining, parsed) = be_name(&buf[9..], buf).unwrap();
        assert_eq!(parsed, "zz.yy.xx");
    }

    #[test]
    fn write_name_compressed_reuses_suffix_pointer() {
        let mut buf = Vec::new();
        let mut ctx = NameCompression::new();

        let first = "www.skype.com".to_string();
        let second = "mail.skype.com".to_string();

        put_name(&mut buf, &first, &mut ctx);
        let second_pos = buf.len();
        put_name(&mut buf, &second, &mut ctx);

        assert_eq!(&buf, b"\x03www\x05skype\x03com\x00\x04mail\xc0\x04");

        let (remain, first_parsed) = be_name(&buf, &buf).unwrap();
        assert_eq!(first_parsed, "www.skype.com");
        assert_eq!(remain.len(), buf.len() - second_pos);

        let (remain, second_parsed) = be_name(&buf[second_pos..], &buf).unwrap();
        assert!(remain.is_empty());
        assert_eq!(second_parsed, "mail.skype.com");
    }

    #[test]
    fn write_name_compressed_prefers_longer_suffix() {
        let mut buf = Vec::new();
        let mut ctx = NameCompression::new();

        let first = "a.b.c.com".to_string();
        let second = "x.c.com".to_string();

        put_name(&mut buf, &first, &mut ctx);
        put_name(&mut buf, &second, &mut ctx);

        assert_eq!(&buf, b"\x01a\x01b\x01c\x03com\x00\x01x\xc0\x04");
    }

    #[test]
    fn write_and_parse_roundtrip() {
        let raw_name = "HP Color LaserJet Pro M478f-9f [EC3C83]._http._tcp.local".to_string();

        let mut buf = Vec::new();
        let mut ctx = NameCompression::new();
        let _ = put_name(&mut buf, &raw_name, &mut ctx);

        let (remaining, parsed) = be_name(&buf, &buf).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(parsed, raw_name);
    }

    #[test]
    fn random_ascii_name_roundtrip_without_compression_pointer() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..1000 {
            let wire = gen_ascii_wire_name(&mut state);
            let (_, name) = be_name(&wire, &wire).unwrap();
            let mut buf = Vec::new();
            let mut ctx = NameCompression::new();
            put_name(&mut buf, &name, &mut ctx);
            assert_eq!(buf, wire);
        }
    }
}
