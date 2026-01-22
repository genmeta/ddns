use std::{collections::HashMap, fmt};

use bytes::BufMut;

use super::{
    header::{Header, be_header},
    question::{QueryClass, QueryType, Question, be_question},
    record::{Class, RData, ResourceRecord, endpoint::EndpointAddr},
};
use crate::parser::{
    header::WriteHeader,
    name::{NameCompression, put_name},
    record::{Type, be_record, endpoint::WriteEndpointAddr, srv::Srv},
};

/// Parsed DNS packet
#[derive(Default, Clone)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub nameservers: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DNS Packet:")?;
        writeln!(
            f,
            "  Header: ID={}, QR={}, AA={}, RCODE={:?}",
            self.header.id,
            self.header.flags.query(),
            self.header.flags.authoritative(),
            self.header.flags.response_code()
        )?;
        if !self.questions.is_empty() {
            writeln!(f, "  Questions:")?;
            for q in &self.questions {
                writeln!(f, "    {} {:?} {:?}", q.name, q.qclass, q.qtype)?;
            }
        }
        if !self.answers.is_empty() {
            writeln!(f, "  Answers:")?;
            for rr in &self.answers {
                write!(f, "    {} {} {:?} {:?}", rr.name, rr.ttl, rr.cls, rr.typ)?;
                match &rr.data {
                    RData::A(ip) => writeln!(f, " A {}", ip)?,
                    RData::AAAA(ip) => writeln!(f, " AAAA {}", ip)?,
                    RData::CName(name) => writeln!(f, " CNAME {}", name)?,
                    RData::E(ep) => {
                        writeln!(f, " E {}", ep.primary)?;
                    }
                    _ => writeln!(f, " {:?}", rr.data)?,
                }
            }
        }
        if !self.nameservers.is_empty() {
            writeln!(f, "  Nameservers:")?;
            for rr in &self.nameservers {
                writeln!(f, "    {} {} {:?} {:?}", rr.name, rr.ttl, rr.cls, rr.typ)?;
            }
        }
        if !self.additional.is_empty() {
            writeln!(f, "  Additional:")?;
            for rr in &self.additional {
                writeln!(f, "    {} {} {:?} {:?}", rr.name, rr.ttl, rr.cls, rr.typ)?;
            }
        }
        Ok(())
    }
}

impl Packet {
    pub fn query_with_id(service_name: String) -> Self {
        let mut packet = Packet::default();
        let id: u16 = rand::random();
        packet.header.id = id;
        packet.header.flags.set_query(false);
        packet.add_question(&service_name, QueryType::A, QueryClass::IN, false);
        packet
    }

    pub fn query(service_name: String) -> Self {
        let mut packet = Self::default();
        packet.add_question(&service_name, QueryType::A, QueryClass::IN, true);
        packet
    }

    pub fn answer(id: u16, hosts: &HashMap<String, Vec<EndpointAddr>>) -> Self {
        let mut packet = Self::default();
        packet.header.id = id;
        packet.header.flags.set_query(true);
        hosts.iter().for_each(|(name, eps)| {
            eps.iter().for_each(|ep| {
                let (rtype, rdata) = (Type::E, RData::E(ep.clone()));
                packet.add_answer(name, rtype, Class::IN, 300, rdata);
            });
        });
        packet
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2048);
        let mut ctx = NameCompression::new();

        buf.put_header(&self.header);

        for question in &self.questions {
            let _ = put_name(&mut buf, &question.name, &mut ctx);
            buf.put_u16(question.qtype.into());
            let mut qclass = u16::from(question.qclass);
            if question.prefer_unicast {
                qclass |= 0x8000;
            }
            buf.put_u16(qclass);
        }

        for answer in &self.answers {
            put_record(&mut buf, answer, &mut ctx);
        }
        for nameserver in &self.nameservers {
            put_record(&mut buf, nameserver, &mut ctx);
        }
        for additional in &self.additional {
            put_record(&mut buf, additional, &mut ctx);
        }

        buf
    }

    fn add_question(
        &mut self,
        qname: &str,
        qtype: QueryType,
        qclass: QueryClass,
        prefer_unicast: bool,
    ) {
        let question = Question {
            name: qname.to_string(),
            prefer_unicast,
            qtype,
            qclass,
        };
        self.header.questions_count += 1;
        self.questions.push(question);
    }

    fn add_answer(&mut self, name: &str, rtype: Type, rclass: Class, ttl: u32, data: RData) {
        let response = ResourceRecord {
            name: name.to_string(),
            typ: rtype,
            multicast_unique: false,
            cls: rclass,
            ttl,
            data,
        };
        // true 代表是 response
        self.header.flags.set_query(true);
        self.header.answers_count += 1;
        self.answers.push(response);
    }
}

fn put_record(buf: &mut Vec<u8>, record: &ResourceRecord, ctx: &mut NameCompression) {
    let _ = put_name(buf, &record.name, ctx);
    buf.put_u16(u16::from(record.typ));

    let mut cls = u16::from(record.cls);
    if record.multicast_unique {
        cls |= 0x8000;
    }
    buf.put_u16(cls);

    buf.put_u32(record.ttl);

    let rdlen_pos = buf.len();
    buf.put_u16(0);
    let rdata_start = buf.len();

    match &record.data {
        RData::A(ip) => buf.put_slice(&ip.octets()),
        RData::AAAA(ip) => buf.put_slice(&ip.octets()),
        RData::CName(name) => {
            let _ = put_name(buf, name, ctx);
        }
        RData::Txt(txt) => buf.put_slice(txt),
        RData::Srv(srv) => put_srv(buf, srv, ctx),
        RData::Ptr(ptr) => {
            let _ = put_name(buf, ptr.name(), ctx);
        }
        RData::E(e) => buf.put_endpoint_addr(e),
    }

    let rdlen = (buf.len() - rdata_start) as u16;
    let [hi, lo] = rdlen.to_be_bytes();
    buf[rdlen_pos] = hi;
    buf[rdlen_pos + 1] = lo;
}

fn put_srv(buf: &mut Vec<u8>, srv: &Srv, ctx: &mut NameCompression) {
    buf.put_u16(srv.priority());
    buf.put_u16(srv.weight());
    buf.put_u16(srv.port());
    let _ = put_name(buf, srv.target(), ctx);
}

pub fn be_packet(input: &[u8]) -> nom::IResult<&[u8], Packet> {
    let (remain, header) = be_header(input)?;

    let (remain, questions) =
        parse::<Question>(remain, input, header.questions_count, be_question)?;
    let (remain, answers) =
        parse::<ResourceRecord>(remain, input, header.answers_count, be_record)?;
    let (remain, nameservers) =
        parse::<ResourceRecord>(remain, input, header.nameservers_count, be_record)?;
    let (remain, additional) =
        parse::<ResourceRecord>(remain, input, header.additional_count, be_record)?;

    Ok((
        remain,
        Packet {
            header,
            questions,
            answers,
            nameservers,
            additional,
        },
    ))
}

fn parse<'a, T>(
    mut input: &'a [u8],
    original: &'a [u8],
    count: u16,
    parser: impl Fn(&'a [u8], &'a [u8]) -> nom::IResult<&'a [u8], T>,
) -> nom::IResult<&'a [u8], Vec<T>> {
    let mut records = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match parser(input, original) {
            Ok((new_input, record)) => {
                records.push(record);
                input = new_input;
            }
            Err(nom::Err::Error(nom::error::Error {
                input: remaining, ..
            })) => {
                input = remaining;
            }
            _ => break,
        }
    }
    Ok((input, records))
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::parser::{
        self,
        question::{QueryClass, QueryType},
        record::{Class, RData, Type, srv::Srv},
    };

    fn decode_hex(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut n = 0u8;
        let mut high = true;
        for b in s.bytes() {
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                b' ' | b'\n' | b'\r' | b'\t' => continue,
                _ => panic!("invalid hex"),
            };
            if high {
                n = v << 4;
                high = false;
            } else {
                n |= v;
                out.push(n);
                high = true;
            }
        }
        if !high {
            panic!("odd hex length");
        }
        out
    }

    #[test]
    fn parse_example_query() {
        let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        let (_, packet) = be_packet(query).unwrap();
        assert_eq!(packet.header.id, 1573);
        assert_eq!(packet.header.questions_count, 1);
        assert_eq!(packet.questions[0].qtype, QueryType::A);
        assert_eq!(packet.questions[0].qclass, QueryClass::IN);
        assert_eq!(packet.questions[0].name.to_string(), "example.com");
        assert_eq!(packet.header.answers_count, 0);
    }

    #[test]
    fn parse_example_response() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xf8\
                         \x00\x04]\xb8\xd8\"";
        let (_, packet) = be_packet(response).unwrap();
        assert_eq!(packet.header.id, 1573);
        assert_eq!(packet.header.questions_count, 1);
        assert_eq!(packet.questions[0].qtype, QueryType::A);
        assert_eq!(packet.questions[0].qclass, QueryClass::IN);
        assert_eq!(packet.questions[0].name.to_string(), "example.com");
        assert_eq!(packet.header.answers_count, 1);
        assert_eq!(packet.answers[0].name.to_string(), "example.com");
        assert_eq!(packet.answers[0].typ, Type::A);
        assert_eq!(packet.answers[0].cls, Class::IN);
        assert_eq!(packet.answers[0].ttl, 1272);
        match &packet.answers[0].data {
            RData::A(addr) => assert_eq!(*addr, Ipv4Addr::new(93, 184, 216, 34)),
            _ => panic!("unexpected rdata"),
        }
    }

    #[test]
    fn parse_response_with_multicast_unique() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x01\x80\x01\x00\x00\x04\xf8\
                         \x00\x04]\xb8\xd8\"";
        let (_, packet) = be_packet(response).unwrap();

        assert_eq!(packet.answers.len(), 1);
        assert!(packet.answers[0].multicast_unique);
        assert_eq!(packet.answers[0].cls, Class::IN);
    }

    #[test]
    fn parse_additional_record_response() {
        tracing_subscriber::fmt().with_ansi(false).init();
        let response = b"\x4a\xf0\x81\x80\x00\x01\x00\x01\x00\x01\x00\x01\
                         \x03www\x05skype\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\
                         \x00\x1c\x07\x6c\x69\x76\x65\x63\x6d\x73\x0e\x74\
                         \x72\x61\x66\x66\x69\x63\x6d\x61\x6e\x61\x67\x65\
                         \x72\x03\x6e\x65\x74\x00\
                         \xc0\x42\x00\x02\x00\x01\x00\x01\xd5\xd3\x00\x11\
                         \x01\x67\x0c\x67\x74\x6c\x64\x2d\x73\x65\x72\x76\x65\x72\x73\
                         \xc0\x42\
                         \x01\x61\xc0\x55\x00\x01\x00\x01\x00\x00\xa3\x1c\
                         \x00\x04\xc0\x05\x06\x1e";
        let (_, packet) = be_packet(response).unwrap();

        assert_eq!(packet.header.id, 19184);
        assert_eq!(packet.header.questions_count, 1);
        assert_eq!(packet.questions[0].qtype, QueryType::A);
        assert_eq!(packet.questions[0].qclass, QueryClass::IN);
        assert_eq!(&packet.questions[0].name.to_string()[..], "www.skype.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "www.skype.com");
        assert_eq!(packet.answers[0].cls, Class::IN);
        assert_eq!(packet.answers[0].ttl, 3600);

        match &packet.answers[0].data {
            RData::CName(cname) => {
                assert_eq!(cname, "livecms.trafficmanager.net");
            }
            ref x => panic!("Wrong rdata {x:?}"),
        }
        assert_eq!(packet.additional.len(), 1);
        assert_eq!(
            &packet.additional[0].name.to_string()[..],
            "a.gtld-servers.net"
        );
        assert_eq!(packet.additional[0].cls, Class::IN);
        assert_eq!(packet.additional[0].ttl, 41756);
        match packet.additional[0].data {
            RData::A(addr) => {
                assert_eq!(addr, Ipv4Addr::new(192, 5, 6, 30));
            }
            ref x => panic!("Wrong rdata {x:?}"),
        }
    }

    #[test]
    fn parse_pack_packet() {
        let mut response = Packet::default();
        let address = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
            )),
        ];
        for ip in address.iter() {
            let (rtype, rdata) = match ip {
                IpAddr::V4(ipv4_addr) => (
                    parser::record::Type::A,
                    parser::record::RData::A(*ipv4_addr),
                ),
                IpAddr::V6(ipv6_addr) => (
                    parser::record::Type::AAAA,
                    parser::record::RData::AAAA(*ipv6_addr),
                ),
            };
            response.add_answer("example.com", rtype, parser::record::Class::IN, 300, rdata);
        }

        let srv = Srv::new(0, 0, 6000, "example.com".to_string());
        response.add_answer(
            "example.com",
            parser::record::Type::Srv,
            parser::record::Class::IN,
            300,
            parser::record::RData::Srv(srv),
        );
        let packet = response.to_bytes();
        let (_, parsed_packet) = be_packet(&packet).unwrap();
        assert_eq!(parsed_packet.header.id, response.header.id);
        assert_eq!(
            parsed_packet.header.questions_count,
            response.header.questions_count
        );
        assert_eq!(parsed_packet.answers.len(), response.answers.len());
        assert_eq!(parsed_packet.nameservers.len(), response.nameservers.len());
        assert_eq!(parsed_packet.additional.len(), response.additional.len());
        assert_eq!(parsed_packet.answers[0].name, response.answers[0].name);
    }

    #[test]
    fn malformed_packet_does_not_panic() {
        let packet_hex = "0021641c0000000100000000000078787878787878787878787303636f6d0000100001";
        let data = decode_hex(packet_hex);
        let ret = std::panic::catch_unwind(|| {
            let _ = be_packet(&data);
        });
        assert!(ret.is_ok());
    }

    #[test]
    fn packet_with_unknown_rr_type_does_not_panic() {
        let packet_hex = "8116840000010001000000000569627a6c700474657374046d69656b026e6c00000a0001c00c000a0001000000000005497f000001";
        let data = decode_hex(packet_hex);
        let ret = std::panic::catch_unwind(|| be_packet(&data));
        assert!(ret.is_ok());
        let (_, packet) = be_packet(&data).unwrap();
        assert_eq!(packet.header.questions_count, 1);
        assert_eq!(packet.header.answers_count, 1);
        assert!(packet.answers.is_empty());
    }

    #[test]
    fn packet_to_bytes_uses_name_compression_across_sections() {
        let mut packet = Packet::default();
        packet.add_question("www.skype.com", QueryType::A, QueryClass::IN, false);
        packet.add_answer(
            "mail.skype.com",
            Type::A,
            Class::IN,
            1,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );

        let bytes = packet.to_bytes();
        let mail_pos = bytes
            .windows(5)
            .position(|w| w == b"\x04mail")
            .expect("mail label missing");
        let skype_pos = bytes
            .windows(6)
            .position(|w| w == b"\x05skype")
            .expect("skype label missing");

        let ptr = (0xC000u16 | (skype_pos as u16)).to_be_bytes();
        assert_eq!(&bytes[mail_pos + 5..mail_pos + 7], &ptr);
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Packet {{ id: {}, qr: {}, opcode: {:?}, rcode: {:?}, questions: {}, answers: {}, authorities: {}, additional: {} }}",
            self.header.id,
            self.header.flags.query(),
            self.header.flags.opcode(),
            self.header.flags.response_code(),
            self.questions.len(),
            self.answers.len(),
            self.nameservers.len(),
            self.additional.len()
        )
    }
}
