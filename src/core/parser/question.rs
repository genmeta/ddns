use std::io;

use nom::number::streaming::be_u16;

use super::name::{Name, be_name};

///
/// ```text
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                     QNAME                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QTYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QCLASS                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ``
#[derive(Debug, Clone)]
pub struct Question {
    pub(crate) name: Name,
    pub(crate) prefer_unicast: bool,
    pub(crate) qtype: QueryType,
    pub(crate) qclass: QueryClass,
}

impl Question {
    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn prefer_unicast(&self) -> bool {
        self.prefer_unicast
    }

    pub fn qtype(&self) -> QueryType {
        self.qtype
    }

    pub fn qclass(&self) -> QueryClass {
        self.qclass
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QueryType {
    /// a host addresss
    A,
    /// IPv6 host address (RFC 2782)
    #[allow(clippy::upper_case_acronyms)]
    AAAA,
    /// the canonical name for an alias
    Cname,
    /// text strings
    Txt,
    /// service record (RFC 2782)
    Srv,
    /// a domain name pointer
    Ptr,
    /// Unassigned 265-32767
    /// 266 a ipv4 address,
    E,
    /// 267 a ipv6 address,
    E6,
    /// 268 a ipv4 relay endpoint,
    EE,
    /// 269 a ipv6 relay endpoint,
    EE6,
}

impl TryFrom<u16> for QueryType {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let query = match value {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::Cname,
            16 => Self::Txt,
            33 => Self::Srv,
            12 => Self::Ptr,
            266 => Self::E,
            267 => Self::E6,
            268 => Self::EE,
            269 => Self::EE6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown query type {value}"),
                ));
            }
        };
        Ok(query)
    }
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::A => 1,
            QueryType::AAAA => 28,
            QueryType::Cname => 5,
            QueryType::Txt => 16,
            QueryType::Srv => 33,
            QueryType::Ptr => 12,
            QueryType::E => 266,
            QueryType::E6 => 267,
            QueryType::EE => 268,
            QueryType::EE6 => 269,
        }
    }
}

/// The QCLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QueryClass {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
    /// Any class
    Any = 255,
}

impl From<QueryClass> for u16 {
    fn from(query: QueryClass) -> u16 {
        match query {
            QueryClass::IN => 1,
            QueryClass::CS => 2,
            QueryClass::CH => 3,
            QueryClass::HS => 4,
            QueryClass::Any => 255,
        }
    }
}

impl TryFrom<u16> for QueryClass {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let query = match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            255 => Self::Any,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown query class {value}"),
                ));
            }
        };
        Ok(query)
    }
}

pub fn be_question<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], Question> {
    let (remain, name) = be_name(input, origin)?;
    let (remain, qtype) = be_u16(remain)?;
    let (remain, qclass) = be_u16(remain)?;

    let Ok(qtype) = QueryType::try_from(qtype) else {
        return Err(nom::Err::Error(nom::error::make_error(
            remain,
            nom::error::ErrorKind::Alt,
        )));
    };
    let prefer_unicast = qclass & 0x8000 == 0x8000;
    let qclass = qclass & 0x7FFF;

    let Ok(qclass) = QueryClass::try_from(qclass) else {
        return Err(nom::Err::Error(nom::error::make_error(
            remain,
            nom::error::ErrorKind::Alt,
        )));
    };
    Ok((
        remain,
        Question {
            name,
            prefer_unicast,
            qtype,
            qclass,
        },
    ))
}
