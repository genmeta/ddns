use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use bytes::Buf;
use endpoint::{EndpointAddr, be_endpoint_addr_compat};
use nom::{
    Parser,
    bytes::streaming::take,
    combinator::map,
    number::streaming::{be_u16, be_u32, be_u128},
};
use ptr::{Ptr, be_ptr};
use srv::{Srv, be_srv};
use tokio::io;
use txt::Txt;

use super::name::{Name, be_name};

pub mod endpoint;
pub mod ptr;
pub mod srv;
pub mod txt;
/// '''text
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                                               /
/// /                      NAME                     /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// /                     RDATA                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// '''
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct ResourceRecord {
    pub(crate) name: Name,
    pub(crate) typ: Type,
    /// Whether or not the set of resource records is fully contained in the
    /// packet, or whether there will be more resource records in future
    /// packets. Only used for multicast DNS.
    pub(crate) multicast_unique: bool,
    pub(crate) cls: Class,
    pub(crate) ttl: u32,
    pub(crate) data: RData,
}

impl ResourceRecord {
    pub fn data(&self) -> &RData {
        &self.data
    }

    pub fn name(&self) -> Name {
        self.name.clone()
    }

    pub fn typ(&self) -> Type {
        self.typ
    }

    pub fn cls(&self) -> Class {
        self.cls
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }
}

/// The CLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Class {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
}

impl TryFrom<u16> for Class {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let value = value & 0x7FFF; // Mask to 15 bits
        let class = match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown record class: {value}"),
                ));
            }
        };
        Ok(class)
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> Self {
        match value {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
        }
    }
}

/// The TYPE value according to RFC 1035
///
/// All "EXPERIMENTAL" markers here are from the RFC
/// See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Type {
    /// 1 a host addresss
    A,
    /// 2 an authoritative name server
    Ns,
    /// 28 IPv6 host address (RFC 2782)
    #[allow(clippy::upper_case_acronyms)]
    AAAA,
    /// 5 the canonical name for an alias
    Cname,
    /// 16 text strings
    Txt,
    /// 33 service record (RFC 2782)
    Srv,
    /// 12 a domain name pointer
    Ptr,
    /// 266 Unified endpoint address (IPv4/IPv6, direct/relay determined by flags)
    E,
}

impl TryFrom<u16> for Type {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let typ = match value {
            1 => Self::A,
            2 => Self::Ns,
            28 => Self::AAAA,
            5 => Self::Cname,
            16 => Self::Txt,
            33 => Self::Srv,
            12 => Self::Ptr,
            266 => Self::E,
            // 保持向后兼容，将旧的类型映射到统一的 E 类型
            267..=269 => Self::E,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown record type: {value}"),
                ));
            }
        };
        Ok(typ)
    }
}

impl From<Type> for u16 {
    fn from(value: Type) -> Self {
        match value {
            Type::A => 1,
            Type::Ns => 2,
            Type::AAAA => 28,
            Type::Cname => 5,
            Type::Txt => 16,
            Type::Srv => 33,
            Type::Ptr => 12,
            Type::E => 266,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CName(Name),
    Txt(Txt),
    Srv(Srv),
    Ptr(Ptr),
    E(EndpointAddr),
}

impl Display for RData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{ip}"),
            RData::AAAA(ip) => write!(f, "{ip}"),
            RData::CName(name) => write!(f, "CName({name})"),
            RData::Txt(txt) => write!(f, "{txt:?})"),
            RData::Srv(srv) => write!(f, "{srv:?}"),
            RData::Ptr(ptr) => write!(f, "{ptr:?}"),
            RData::E(e) => write!(f, "{e}"),
        }
    }
}

pub fn be_record<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], ResourceRecord> {
    let (remain, name) = be_name(input, origin)?;
    let (remain, typ) = be_u16(remain)?;
    let (remain, cls) = be_u16(remain)?;
    let (remain, ttl) = be_u32(remain)?;
    let (mut remain, rdlen) = be_u16(remain)?;

    let Ok(typ) = Type::try_from(typ) else {
        if remain.len() < rdlen as usize {
            return Err(nom::Err::Incomplete(nom::Needed::new(
                rdlen as usize - remain.len(),
            )));
        }
        remain.advance(rdlen as usize);
        return Err(nom::Err::Error(nom::error::make_error(
            remain,
            nom::error::ErrorKind::Alt,
        )));
    };

    if remain.len() < rdlen as usize {
        return Err(nom::Err::Incomplete(nom::Needed::new(
            rdlen as usize - remain.len(),
        )));
    }
    let (remain_after_rdata, rdata_bytes) = take(rdlen)(remain)?;
    let (rdata_remain, rdata) = be_rdata(rdata_bytes, origin, typ, rdlen)?;
    if !rdata_remain.is_empty() {
        return Err(nom::Err::Error(nom::error::make_error(
            remain_after_rdata,
            nom::error::ErrorKind::Eof,
        )));
    }
    let mut remain = remain_after_rdata;

    let multicast_unique = cls & 0x8000 == 0x8000;
    let cls = cls & 0x7FFF;
    let Ok(cls) = Class::try_from(cls) else {
        if remain.len() < rdlen as usize {
            return Err(nom::Err::Incomplete(nom::Needed::new(
                rdlen as usize - remain.len(),
            )));
        }
        remain.advance(rdlen as usize);
        return Err(nom::Err::Error(nom::error::make_error(
            remain,
            nom::error::ErrorKind::Alt,
        )));
    };

    Ok((
        remain,
        ResourceRecord {
            name,
            typ,
            multicast_unique,
            cls,
            ttl,
            data: rdata,
        },
    ))
}

fn be_rdata<'a>(
    input: &'a [u8],
    origin: &'a [u8],
    typ: Type,
    rdlen: u16,
) -> nom::IResult<&'a [u8], RData> {
    match typ {
        Type::A => map(be_u32, |ip| RData::A(Ipv4Addr::from(ip))).parse(input),
        Type::AAAA => map(be_u128, |ip| RData::AAAA(Ipv6Addr::from(ip))).parse(input),
        Type::Cname => be_name(input, origin).map(|(remain, name)| (remain, RData::CName(name))),
        Type::Txt => map(take(rdlen), |txt: &[u8]| RData::Txt(Txt::new(txt.to_vec()))).parse(input),
        Type::Srv => {
            let (remain, srv) = be_srv(input, origin)?;
            Ok((remain, RData::Srv(srv)))
        }
        Type::Ptr => be_ptr(input, origin).map(|(remain, ptr)| (remain, RData::Ptr(ptr))),
        Type::Ns => be_name(input, origin).map(|(remain, name)| (remain, RData::CName(name))),
        Type::E => be_endpoint_addr_compat(input, rdlen).map(|(remain, e)| (remain, RData::E(e))),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn record_prefix_for_a(name: &[u8], rdlen: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(name);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&rdlen.to_be_bytes());
        buf
    }

    #[test]
    fn parse_record_incomplete_rdata_returns_incomplete() {
        let name = b"\x07example\x03com\x00";
        let mut buf = record_prefix_for_a(name, 4);
        buf.extend_from_slice(&[127, 0, 0]);
        let ret = be_record(&buf, &buf);
        assert!(matches!(ret, Err(nom::Err::Incomplete(_))));
    }

    #[test]
    fn parse_record_extra_rdata_bytes_is_error() {
        let name = b"\x07example\x03com\x00";
        let mut buf = record_prefix_for_a(name, 5);
        buf.extend_from_slice(&[127, 0, 0, 1, 9]);
        let ret = be_record(&buf, &buf);
        assert!(matches!(ret, Err(nom::Err::Error(_))));
    }
}
