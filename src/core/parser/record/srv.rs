use nom::number::streaming::be_u16;

use crate::parser::name::{Name, be_name};

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Srv {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name,
}

impl Srv {
    pub fn new(priority: u16, weight: u16, port: u16, target: Name) -> Self {
        Self {
            priority,
            weight,
            port,
            target,
        }
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn target(&self) -> &Name {
        &self.target
    }
}

pub fn be_srv<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], Srv> {
    let (remain, priority) = be_u16(input)?;
    let (remain, weight) = be_u16(remain)?;
    let (remain, port) = be_u16(remain)?;
    let (remain, target) = be_name(remain, origin)?;
    Ok((
        remain,
        Srv {
            priority,
            weight,
            port,
            target,
        },
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::{
        packet::be_packet,
        question::{QueryClass, QueryType},
        record::{Class, RData},
    };
    #[test]
    fn parse_response() {
        let response = b"[\xd9\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\
            \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00 \x00\x05\x00\x00\
            \x14\x95\x0bxmpp-server\x01l\x06google\x03com\x00\xc0\x0c\x00!\
            \x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\x14\x95\
            \x04alt3\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt1\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt2\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt4\x0bxmpp-server\x01l\x06google\x03com\x00";

        let (_, packet) = be_packet(response).unwrap();

        assert_eq!(packet.header.id, 23513);
        assert_eq!(packet.header.questions_count, 1);
        assert!(packet.header.flags.recursion_desired());
        assert_eq!(packet.header.answers_count, 5);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QueryType::Srv);
        assert_eq!(packet.questions[0].qclass, QueryClass::IN);
        assert_eq!(
            &packet.questions[0].name.to_string()[..],
            "_xmpp-server._tcp.gmail.com"
        );
        assert_eq!(packet.answers.len(), 5);
        let items = [
            (5, 0, 5269, "xmpp-server.l.google.com"),
            (20, 0, 5269, "alt3.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt1.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt2.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt4.xmpp-server.l.google.com"),
        ];
        for (i, item) in items.iter().enumerate() {
            assert_eq!(
                &packet.answers[i].name.to_string()[..],
                "_xmpp-server._tcp.gmail.com"
            );
            assert_eq!(packet.answers[i].cls, Class::IN);
            assert_eq!(packet.answers[i].ttl, 900);
            match &packet.answers[i].data {
                RData::Srv(Srv {
                    priority,
                    weight,
                    port,
                    target,
                }) => {
                    assert_eq!(priority, &item.0);
                    assert_eq!(weight, &item.1);
                    assert_eq!(port, &item.2);
                    assert_eq!(target.to_string(), item.3);
                }
                _ => panic!("Wrong rdata"),
            }
        }
    }
}
