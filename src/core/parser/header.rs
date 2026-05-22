#![allow(clippy::double_parens)]
use bitfield_struct::bitfield;
use bytes::BufMut;
use nom::number::streaming::be_u16;

/// See https://datatracker.ietf.org/doc/html/rfc1035#autoid-40
/// 与标准 DNS 不同，flags 字段的 zero 3bits 后两 bits 用于 AD、CD
/// /// See https://datatracker.ietf.org/doc/html/rfc6762#autoid-48
/// ```text
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone)]
pub struct Header {
    pub(crate) id: u16,
    pub(crate) flags: Flags,
    pub(crate) questions_count: u16,
    pub(crate) answers_count: u16,
    pub(crate) nameservers_count: u16,
    pub(crate) additional_count: u16,
}

impl Default for Header {
    fn default() -> Self {
        let flags = Flags::new();
        flags.with_query(false).set_opcode(Opcode::StandardQuery);
        Self {
            id: 0,
            flags,
            questions_count: 0,
            answers_count: 0,
            nameservers_count: 0,
            additional_count: 0,
        }
    }
}

/// See https://datatracker.ietf.org/doc/html/rfc6762#autoid-48
#[bitfield(u16, order = Msb)]
#[derive(PartialEq, Eq)]
pub struct Flags {
    pub(crate) query: bool,
    #[bits(4)]
    pub(crate) opcode: Opcode,
    pub(crate) authoritative: bool,
    pub(crate) trun_cache: bool,
    pub(crate) recursion_desired: bool,
    pub(crate) recursion_available: bool,
    pub(crate) zero: bool,
    pub(crate) authenticated_data: bool,
    pub(crate) checking_disabled: bool,
    #[bits(4)]
    pub(crate) response_code: ResponseCode,
}

/// The OPCODE value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum Opcode {
    /// Normal query
    StandardQuery = 0,
    /// Inverse query (query a name by IP)
    InverseQuery = 1,
    /// Server status request
    ServerStatusRequest = 2,
    /// Reserved opcode for future use
    Reserved(u8),
}

impl Opcode {
    const fn into_bits(self) -> u8 {
        match self {
            Self::StandardQuery => 0,
            Self::InverseQuery => 1,
            Self::ServerStatusRequest => 2,
            Self::Reserved(value) => value,
        }
    }

    const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::StandardQuery,
            1 => Self::InverseQuery,
            2 => Self::ServerStatusRequest,
            _ => Self::Reserved(value),
        }
    }
}

// The RCODE value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Reserved(u8),
}

impl ResponseCode {
    const fn into_bits(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::Reserved(value) => value,
        }
    }

    const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            _ => Self::Reserved(value),
        }
    }
}

pub fn be_header(input: &[u8]) -> nom::IResult<&[u8], Header> {
    let (remain, id) = be_u16(input)?;
    let (remain, flags) = be_u16(remain)?;
    let flags = Flags::from(flags);
    let (remain, questions) = be_u16(remain)?;
    let (remain, answers) = be_u16(remain)?;
    let (remain, nameservers) = be_u16(remain)?;
    let (remain, additional) = be_u16(remain)?;
    Ok((
        remain,
        Header {
            id,
            flags,
            questions_count: questions,
            answers_count: answers,
            nameservers_count: nameservers,
            additional_count: additional,
        },
    ))
}

pub trait WriteHeader {
    fn put_header(&mut self, header: &Header);
}

impl<T: BufMut> WriteHeader for T {
    fn put_header(&mut self, header: &Header) {
        self.put_u16(header.id);
        self.put_u16(header.flags.into());
        self.put_u16(header.questions_count);
        self.put_u16(header.answers_count);
        self.put_u16(header.nameservers_count);
        self.put_u16(header.additional_count);
    }
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;
    use nom::AsBytes;

    use super::*;

    #[test]
    fn parse_example_query() {
        let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";

        let (remain, header) = be_header(query).unwrap();
        assert_eq!(remain.len(), query.len() - 12);
        assert_eq!(header.id, 1573);
        assert_eq!(header.questions_count, 1);
        assert_eq!(header.answers_count, 0);
        assert_eq!(header.nameservers_count, 0);
        assert_eq!(header.additional_count, 0);
        let flags = Flags::new()
            .with_recursion_desired(true)
            .with_response_code(ResponseCode::NoError)
            .with_opcode(Opcode::StandardQuery);
        assert_eq!(header.flags.into_bits(), 0x0100);
        assert_eq!(header.flags, flags);
    }

    #[test]
    fn parse_example_response() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                     \x07example\x03com\x00\x00\x01\x00\x01\
                     \xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xf8\
                     \x00\x04]\xb8\xd8\"";

        let (remain, header) = be_header(response).unwrap();
        assert_eq!(remain.len(), response.len() - 12);
        assert_eq!(header.id, 1573);
        assert_eq!(header.questions_count, 1);
        assert_eq!(header.answers_count, 1);
        assert_eq!(header.nameservers_count, 0);
        assert_eq!(header.additional_count, 0);
        // response
        let flag = Flags::new()
            .with_recursion_desired(true)
            .with_recursion_available(true)
            .with_query(true)
            .with_response_code(ResponseCode::NoError)
            .with_opcode(Opcode::StandardQuery);
        assert_eq!(header.flags.into_bits(), 0x8180);
        assert_eq!(header.flags, flag);
    }

    #[test]
    fn parse_query_with_ad_set() {
        let query = b"\x06%\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\
                  \x07example\x03com\x00\x00\x01\x00\x01";
        let (remain, header) = be_header(query).unwrap();
        assert_eq!(remain.len(), query.len() - 12);
        assert_eq!(header.id, 1573);
        assert_eq!(header.questions_count, 1);
        assert_eq!(header.answers_count, 0);
        assert_eq!(header.nameservers_count, 0);
        assert_eq!(header.additional_count, 0);

        let flags = Flags::new()
            .with_recursion_desired(true)
            .with_authenticated_data(true)
            .with_response_code(ResponseCode::NoError)
            .with_opcode(Opcode::StandardQuery);
        assert_eq!(header.flags.into_bits(), 0x0120);
        assert_eq!(header.flags, flags);
    }

    #[test]
    fn parse_query_with_cd_set() {
        let query = b"\x06%\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        let (remain, header) = be_header(query).unwrap();
        assert_eq!(remain.len(), query.len() - 12);
        assert_eq!(header.id, 1573);
        assert_eq!(header.questions_count, 1);
        assert_eq!(header.answers_count, 0);
        assert_eq!(header.nameservers_count, 0);
        assert_eq!(header.additional_count, 0);
        let flags = Flags::new()
            .with_recursion_desired(true)
            .with_checking_disabled(true)
            .with_response_code(ResponseCode::NoError)
            .with_opcode(Opcode::StandardQuery);
        assert_eq!(header.flags.into_bits(), 0x0110);
        assert_eq!(header.flags, flags);
    }

    #[test]
    fn write_example_query() {
        let header = Header {
            id: 1573,
            flags: Flags::from(0x0100),
            questions_count: 1,
            answers_count: 0,
            nameservers_count: 0,
            additional_count: 0,
        };
        let mut buf = BytesMut::with_capacity(12);
        buf.put_header(&header);
        assert_eq!(
            buf.as_bytes(),
            b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        );
    }

    #[test]
    fn write_example_response() {
        let header = Header {
            id: 1573,
            flags: Flags::from(0x8180),
            questions_count: 1,
            answers_count: 1,
            nameservers_count: 0,
            additional_count: 0,
        };
        let mut buf = BytesMut::with_capacity(28);
        buf.put_header(&header);
        assert_eq!(
            buf.as_bytes(),
            b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        );
    }
}
