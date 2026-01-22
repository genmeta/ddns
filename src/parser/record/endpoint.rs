use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use bytes::BufMut;
use nom::{
    IResult, Parser,
    bytes::streaming::take,
    combinator::{flat_map, map},
    error::{ErrorKind, make_error},
    number::streaming::{be_u8, be_u16, be_u32, be_u128},
};
use rustls::{SignatureScheme, pki_types::SubjectPublicKeyInfoDer, sign::SigningKey};

use crate::parser::{
    sigin,
    varint::{VarInt, WriteVarInt, be_varint},
};

/// EndpointAddress record (Type E = 266)
///
/// Unified endpoint format that encodes IPv4/IPv6 and direct/relay information in flags.
///
/// ## RDATA 线协议格式
///
/// ### 包格式
///
/// ```text
/// +--------+-----------------+--------------------+----------------------------+
/// | flags  | sequence(varint)| addr(s)            | signature (optional)       |
/// +--------+-----------------+--------------------+----------------------------+
/// | u8     | QUIC varint     | v4: 2+4 / v6: 2+16 | scheme(u16)+len(varint)+N  |
/// +--------+-----------------+--------------------+----------------------------+
/// ```
///
/// ### flags (u8) 字段定义:
/// - bit 7 (0x80): FAMILY - 0=IPv4, 1=IPv6
/// - bit 6 (0x40): MAIN - 主地址标志
/// - bit 5 (0x20): SEQUENCED - 是否有序号
/// - bit 4 (0x10): FORWARD - 0=直连, 1=中转
/// - bit 3 (0x08): SIGNED - 是否有签名标志
/// - bits 2-0: 保留位
///
/// ### 地址格式:
/// - 直连: `port(u16)` + `IP(u32/u128)`
/// - 中转: `outer_port(u16)` + `outer_IP(u32/u128)` + `agent_port(u16)` + `agent_IP(u32/u128)`
/// - `sequence`: DNS 记录编号，同一编号的记录视为一个机器，可以使用多路径连接
/// - `signature`: 当 `SIGNED` 置位时，允许附加签名字段
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointSignature {
    scheme: u16,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointAddr {
    flags: u8,
    /// 序号，用于多路径连接，None 表示无序号
    sequence: Option<VarInt>,
    signature: Option<EndpointSignature>,
    /// 主地址 (直连时为唯一地址，中转时为外部地址)
    pub primary: SocketAddr,
    /// 代理地址 (仅中转时使用)
    pub agent: Option<SocketAddr>,
}

impl EndpointAddr {
    const FLAG_FAMILY: u8 = 0b1000_0000; // 0=IPv4, 1=IPv6
    const FLAG_MAIN: u8 = 0b0100_0000;
    const FLAG_SEQUENCED: u8 = 0b0010_0000;
    const FLAG_FORWARD: u8 = 0b0001_0000; // 0=直连, 1=中转
    const FLAG_SIGNED: u8 = 0b0000_1000;

    pub fn direct_v4(addr: SocketAddrV4) -> Self {
        Self {
            flags: 0, // IPv4 直连: family=0, forward=0
            sequence: None,
            signature: None,
            primary: addr.into(),
            agent: None,
        }
    }

    pub fn direct_v6(addr: SocketAddrV6) -> Self {
        Self {
            flags: Self::FLAG_FAMILY, // IPv6 直连: family=1, forward=0
            sequence: None,
            signature: None,
            primary: addr.into(),
            agent: None,
        }
    }

    pub fn relay_v4(outer: SocketAddrV4, agent: SocketAddrV4) -> Self {
        Self {
            flags: Self::FLAG_FORWARD, // IPv4 中转: family=0, forward=1
            sequence: None,
            signature: None,
            primary: outer.into(),
            agent: Some(agent.into()),
        }
    }

    pub fn relay_v6(outer: SocketAddrV6, agent: SocketAddrV6) -> Self {
        Self {
            flags: Self::FLAG_FAMILY | Self::FLAG_FORWARD, // IPv6 中转: family=1, forward=1
            sequence: None,
            signature: None,
            primary: outer.into(),
            agent: Some(agent.into()),
        }
    }

    /// 是否为 IPv6 地址
    pub fn is_ipv6(&self) -> bool {
        self.flags & Self::FLAG_FAMILY != 0
    }

    /// 是否为中转地址
    pub fn is_relay(&self) -> bool {
        self.flags & Self::FLAG_FORWARD != 0
    }

    /// 是否有序号
    pub fn is_sequenced(&self) -> bool {
        self.flags & Self::FLAG_SEQUENCED != 0
    }

    pub fn set_sequenced(&mut self, sequenced: bool) {
        if sequenced {
            self.flags |= Self::FLAG_SEQUENCED;
        } else {
            self.flags &= !Self::FLAG_SEQUENCED;
            self.sequence = None; // 清除序号
        }
    }

    pub fn sign_with(
        &mut self,
        key: &(impl SigningKey + ?Sized),
        scheme: SignatureScheme,
    ) -> Result<(), sigin::SignError> {
        self.set_signed(true);
        let data = self.signed_data();
        let signature = sigin::sign(key, scheme, &data)?;
        self.signature = Some(EndpointSignature {
            scheme: u16::from(scheme),
            signature,
        });
        Ok(())
    }

    pub fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoDer<'_>,
    ) -> Result<bool, sigin::VerifyError> {
        let Some(sig) = &self.signature else {
            return Ok(false);
        };
        let data = self.signed_data();
        sigin::verify(
            spki,
            SignatureScheme::from(sig.scheme),
            &data,
            &sig.signature,
        )
    }

    pub fn is_main(&self) -> bool {
        self.flags() & Self::FLAG_MAIN == Self::FLAG_MAIN
    }

    pub fn set_main(&mut self, is_main: bool) {
        let flags = self.flags_mut();
        if is_main {
            *flags |= Self::FLAG_MAIN;
        } else {
            *flags &= !Self::FLAG_MAIN;
        }
    }

    pub fn is_signed(&self) -> bool {
        self.flags() & Self::FLAG_SIGNED == Self::FLAG_SIGNED
    }

    pub fn set_signed(&mut self, is_signed: bool) {
        let flags = self.flags_mut();
        if is_signed {
            *flags |= Self::FLAG_SIGNED;
        } else {
            *flags &= !Self::FLAG_SIGNED;
        }
    }

    pub fn encpding_size(&self) -> usize {
        let mut meta_len = 1; // flags

        // sequence 只有在存在时才编码
        if let Some(seq) = &self.sequence {
            meta_len += seq.encoding_size();
        }

        if self.is_signed()
            && let Some(sig) = &self.signature
        {
            let sig_len =
                VarInt::try_from(sig.signature.len() as u64).unwrap_or(VarInt::from_u32(0));
            meta_len += 2 + sig_len.encoding_size() + sig.signature.len();
        }

        let addr_len = match (self.is_ipv6(), self.is_relay()) {
            (false, false) => 2 + 4,      // IPv4 直连: port + ipv4
            (false, true) => (2 + 4) * 2, // IPv4 中转: (port + ipv4) * 2
            (true, false) => 2 + 16,      // IPv6 直连: port + ipv6
            (true, true) => (2 + 16) * 2, // IPv6 中转: (port + ipv6) * 2
        };

        meta_len + addr_len
    }

    pub fn addr(&self) -> SocketAddr {
        self.primary
    }

    pub fn agent_addr(&self) -> Option<SocketAddr> {
        self.agent
    }

    pub fn set_sequence(&mut self, sequence: u64) {
        if sequence > 0 {
            self.sequence = Some(VarInt::from_u64(sequence).expect("Sequence too large"));
            self.set_sequenced(true);
        } else {
            self.sequence = None;
            self.set_sequenced(false);
        }
    }

    fn flags(&self) -> u8 {
        self.flags
    }

    fn flags_mut(&mut self) -> &mut u8 {
        &mut self.flags
    }

    pub fn signature(&self) -> Option<&EndpointSignature> {
        self.signature.as_ref()
    }

    fn write_base<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.flags);

        // 只有在存在 sequence 时才写入
        if let Some(seq) = &self.sequence {
            buf.put_varint(*seq);
        }

        // 写入主地址
        match self.primary {
            SocketAddr::V4(addr) => buf.put_socket_addr_v4(&addr),
            SocketAddr::V6(addr) => buf.put_socket_addr_v6(&addr),
        }

        // 如果是中转，写入代理地址
        if let Some(agent_addr) = &self.agent {
            match agent_addr {
                SocketAddr::V4(addr) => buf.put_socket_addr_v4(addr),
                SocketAddr::V6(addr) => buf.put_socket_addr_v6(addr),
            }
        }
    }

    fn signed_data(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.set_signed(true);
        unsigned.signature = None;
        let mut buf = bytes::BytesMut::with_capacity(unsigned.encpding_size());
        unsigned.write_base(&mut buf);
        buf.to_vec()
    }
}

pub(crate) trait WriteEndpointAddr {
    fn put_endpoint_addr(&mut self, endpoint: &EndpointAddr);
}

impl<B: BufMut> WriteEndpointAddr for B {
    fn put_endpoint_addr(&mut self, endpoint: &EndpointAddr) {
        endpoint.write_base(self);
        if endpoint.is_signed()
            && let Some(sig) = endpoint.signature()
        {
            self.put_u16(sig.scheme);
            let len = VarInt::try_from(sig.signature.len() as u64).unwrap_or(VarInt::from_u32(0));
            self.put_varint(len);
            self.put_slice(&sig.signature);
        }
    }
}

pub fn be_endpoint_addr(input: &[u8]) -> nom::IResult<&[u8], EndpointAddr> {
    let (remain, flags) = be_u8(input)?;

    let is_sequenced = flags & EndpointAddr::FLAG_SEQUENCED != 0;
    let is_ipv6 = flags & EndpointAddr::FLAG_FAMILY != 0;
    let is_relay = flags & EndpointAddr::FLAG_FORWARD != 0;

    // 只有在 SEQUENCED 标志位设置时才解析 sequence
    let (remain, sequence) = if is_sequenced {
        let (remain, seq) = be_varint(remain)?;
        (remain, Some(seq))
    } else {
        (remain, None)
    };

    let (remain, primary) = if is_ipv6 {
        let (remain, addr) = be_socket_addr_v6(remain)?;
        (remain, SocketAddr::V6(addr))
    } else {
        let (remain, addr) = be_socket_addr_v4(remain)?;
        (remain, SocketAddr::V4(addr))
    };

    let (remain, agent) = if is_relay {
        let agent_addr = if is_ipv6 {
            let (remain, addr) = be_socket_addr_v6(remain)?;
            (remain, SocketAddr::V6(addr))
        } else {
            let (remain, addr) = be_socket_addr_v4(remain)?;
            (remain, SocketAddr::V4(addr))
        };
        let (remain, addr) = agent_addr;
        (remain, Some(addr))
    } else {
        (remain, None)
    };

    let (remain, signature) = be_endpoint_signature(remain, flags)?;

    Ok((
        remain,
        EndpointAddr {
            flags,
            sequence,
            signature,
            primary,
            agent,
        },
    ))
}

/// 兼容解析 EndpointAddr：
///
/// - 当 `rdlen` 匹配 Legacy 的固定长度时，按地址-only 解析，并补全默认 `EndpointMeta`
/// - 否则按 Modern v0（带 `flags` + `sequence`）解析
///
/// 注意：
/// - Legacy 与 Modern 的开头字节序列不同，不能通过窥探 `flags` 来可靠区分
/// - 这里依赖 `RDLENGTH` 的长度判别，避免把端口高字节误当成 `flags`
pub(crate) fn be_endpoint_addr_compat(
    input: &[u8],
    rdlen: u16,
) -> nom::IResult<&[u8], EndpointAddr> {
    // 检查是否为 legacy 格式的固定长度
    let legacy_lengths = [
        6,  // IPv4 直连: port(2) + ip(4)
        12, // IPv4 中转: (port(2) + ip(4)) * 2
        18, // IPv6 直连: port(2) + ip(16)
        36, // IPv6 中转: (port(2) + ip(16)) * 2
    ];

    if legacy_lengths.contains(&(rdlen as usize)) {
        // 尝试 legacy 解析
        return be_legacy_endpoint_addr_by_length(input, rdlen);
    }

    // 现代格式解析
    be_endpoint_addr(input)
}

/// 根据长度解析 Legacy 格式的端点地址
fn be_legacy_endpoint_addr_by_length(
    input: &[u8],
    rdlen: u16,
) -> nom::IResult<&[u8], EndpointAddr> {
    match rdlen {
        6 => {
            // IPv4 直连
            let (remain, addr) = be_socket_addr_v4(input)?;
            Ok((
                remain,
                EndpointAddr {
                    flags: 0, // IPv4 直连
                    sequence: None,
                    signature: None,
                    primary: addr.into(),
                    agent: None,
                },
            ))
        }
        12 => {
            // IPv4 中转
            let (remain, primary) = be_socket_addr_v4(input)?;
            let (remain, agent) = be_socket_addr_v4(remain)?;
            Ok((
                remain,
                EndpointAddr {
                    flags: EndpointAddr::FLAG_FORWARD, // IPv4 中转
                    sequence: None,
                    signature: None,
                    primary: primary.into(),
                    agent: Some(agent.into()),
                },
            ))
        }
        18 => {
            // IPv6 直连
            let (remain, addr) = be_socket_addr_v6(input)?;
            Ok((
                remain,
                EndpointAddr {
                    flags: EndpointAddr::FLAG_FAMILY, // IPv6 直连
                    sequence: None,
                    signature: None,
                    primary: addr.into(),
                    agent: None,
                },
            ))
        }
        36 => {
            // IPv6 中转
            let (remain, primary) = be_socket_addr_v6(input)?;
            let (remain, agent) = be_socket_addr_v6(remain)?;
            Ok((
                remain,
                EndpointAddr {
                    flags: EndpointAddr::FLAG_FAMILY | EndpointAddr::FLAG_FORWARD, // IPv6 中转
                    sequence: None,
                    signature: None,
                    primary: primary.into(),
                    agent: Some(agent.into()),
                },
            ))
        }
        _ => Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::LengthValue,
        ))),
    }
}

fn be_endpoint_signature(input: &[u8], flags: u8) -> IResult<&[u8], Option<EndpointSignature>> {
    if (flags & EndpointAddr::FLAG_SIGNED) != EndpointAddr::FLAG_SIGNED {
        if !input.is_empty() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        return Ok((input, None));
    }

    if input.is_empty() {
        return Ok((input, None));
    }

    let (remain, scheme_u16) = be_u16(input)?;
    let (remain, sig_len) = be_varint(remain)?;
    let sig_len = usize::try_from(sig_len.into_inner())
        .map_err(|_| nom::Err::Error(make_error(remain, ErrorKind::TooLarge)))?;
    let (remain, sig) = take(sig_len)(remain)?;
    Ok((
        remain,
        Some(EndpointSignature {
            scheme: scheme_u16,
            signature: sig.to_vec(),
        }),
    ))
}

pub trait WriteSocketAddr {
    fn put_socket_addr_v4(&mut self, addr: &SocketAddrV4);

    fn put_socket_addr_v6(&mut self, addr: &SocketAddrV6);

    fn put_socket_addr(&mut self, addr: &SocketAddr) {
        match addr {
            SocketAddr::V4(v4) => self.put_socket_addr_v4(v4),
            SocketAddr::V6(v6) => self.put_socket_addr_v6(v6),
        }
    }
}

impl<T: BufMut> WriteSocketAddr for T {
    fn put_socket_addr_v4(&mut self, addr: &SocketAddrV4) {
        self.put_u16(addr.port());
        self.put_u32(u32::from(*addr.ip()));
    }

    fn put_socket_addr_v6(&mut self, addr: &SocketAddrV6) {
        self.put_u16(addr.port());
        self.put_u128(u128::from(*addr.ip()));
    }
}

pub fn be_socket_addr_v4(input: &[u8]) -> IResult<&[u8], SocketAddrV4> {
    flat_map(be_u16, |port| {
        map(be_ipv4_addr, move |ip| SocketAddrV4::new(ip, port))
    })
    .parse(input)
}

pub fn be_socket_addr_v6(input: &[u8]) -> IResult<&[u8], SocketAddrV6> {
    flat_map(be_u16, |port| {
        map(be_ipv6_addr, move |ip| SocketAddrV6::new(ip, port, 0, 0))
    })
    .parse(input)
}

pub fn be_ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    map(be_u32, Ipv4Addr::from).parse(input)
}

pub fn be_ipv6_addr(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    map(be_u128, Ipv6Addr::from).parse(input)
}

pub fn be_ip_addr(is_v6: bool) -> impl Fn(&[u8]) -> IResult<&[u8], IpAddr> {
    move |input| match is_v6 {
        true => map(be_u128, |ip| IpAddr::V6(Ipv6Addr::from(ip))).parse(input),
        false => map(be_u32, |ip| IpAddr::V4(Ipv4Addr::from(ip))).parse(input),
    }
}

impl Display for EndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(agent_addr) = &self.agent {
            write!(f, "{}-{agent_addr}", self.primary)
        } else {
            write!(f, "{}", self.primary)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use bytes::BytesMut;
    use ring::signature::KeyPair;
    use rustls::sign::Signer;

    use super::*;

    #[test]
    fn legacy_endpoint_v4_direct_without_meta() {
        let port = 5353u16;
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&u32::from(ip).to_be_bytes());
        let (remain, decoded) = be_endpoint_addr_compat(&buf, 6).unwrap();
        assert!(remain.is_empty());
        assert_eq!(
            decoded,
            EndpointAddr::direct_v4(SocketAddrV4::new(ip, port))
        );
    }

    #[test]
    fn legacy_endpoint_v4_relay_without_meta() {
        let outer = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1000);
        let agent = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2000);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&outer.port().to_be_bytes());
        buf.extend_from_slice(&u32::from(*outer.ip()).to_be_bytes());
        buf.extend_from_slice(&agent.port().to_be_bytes());
        buf.extend_from_slice(&u32::from(*agent.ip()).to_be_bytes());
        let (remain, decoded) = be_endpoint_addr_compat(&buf, 12).unwrap();
        assert!(remain.is_empty());
        assert_eq!(decoded, EndpointAddr::relay_v4(outer, agent));
    }

    #[test]
    fn flag_bit_ops_work() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 5353);
        let mut ep = EndpointAddr {
            flags: 0b0011_0111,
            sequence: None,
            signature: None,
            primary: addr.into(),
            agent: None,
        };

        assert!(!ep.is_main());
        assert!(!ep.is_signed());

        ep.set_main(true);
        assert!(ep.is_main());
        assert_eq!(ep.flags, 0b0111_0111);

        ep.set_signed(true);
        assert!(ep.is_signed());
        assert_eq!(ep.flags, 0b0111_1111);

        ep.set_main(false);
        assert!(!ep.is_main());
        assert!(ep.is_signed());
        assert_eq!(ep.flags, 0b0011_1111);

        ep.set_signed(false);
        assert!(!ep.is_signed());
        assert_eq!(ep.flags, 0b0011_0111);
    }

    #[test]
    fn varint_roundtrip_and_len() {
        fn roundtrip(v: u64) {
            let v = VarInt::from_u64(v).unwrap();
            let mut buf = BytesMut::new();
            buf.put_varint(v);
            assert_eq!(buf.len(), v.encoding_size());
            let (remain, decoded) = be_varint(&buf).unwrap();
            assert!(remain.is_empty());
            assert_eq!(decoded, v);
        }

        for v in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            roundtrip(v);
        }
    }

    #[test]
    fn varint_rejects_overflow_and_incomplete() {
        assert!(VarInt::from_u64((1 << 62) + 1).is_err());

        let incomplete = [0b01_000000u8];
        match be_varint(&incomplete) {
            Err(nom::Err::Incomplete(_)) => {}
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_encode_decode_roundtrip() {
        let v4_outer = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1000);
        let v4_agent = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2000);
        let v6_outer = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3000, 0, 0);
        let v6_agent = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 4000, 0, 0);

        let cases = [
            // IPv4 直连，带 MAIN 和 SEQUENCED 标志
            EndpointAddr {
                flags: EndpointAddr::FLAG_MAIN | EndpointAddr::FLAG_SEQUENCED,
                sequence: Some(VarInt::from_u32(0)),
                signature: None,
                primary: v4_outer.into(),
                agent: None,
            },
            // IPv4 中转，带 SIGNED 和 SEQUENCED 标志
            EndpointAddr {
                flags: EndpointAddr::FLAG_FORWARD
                    | EndpointAddr::FLAG_SIGNED
                    | EndpointAddr::FLAG_SEQUENCED,
                sequence: Some(VarInt::from_u32(127)),
                signature: None,
                primary: v4_outer.into(),
                agent: Some(v4_agent.into()),
            },
            // IPv6 直连，带 MAIN 和 SEQUENCED 标志
            EndpointAddr {
                flags: EndpointAddr::FLAG_FAMILY
                    | EndpointAddr::FLAG_MAIN
                    | EndpointAddr::FLAG_SEQUENCED,
                sequence: Some(VarInt::from_u32(128)),
                signature: None,
                primary: v6_outer.into(),
                agent: None,
            },
            // IPv6 中转，带 SEQUENCED 标志
            EndpointAddr {
                flags: EndpointAddr::FLAG_FAMILY
                    | EndpointAddr::FLAG_FORWARD
                    | EndpointAddr::FLAG_SEQUENCED,
                sequence: Some(VarInt::from_u64((1 << 62) - 1).unwrap()),
                signature: None,
                primary: v6_outer.into(),
                agent: Some(v6_agent.into()),
            },
        ];

        for ep in cases {
            let mut buf = BytesMut::new();
            buf.put_endpoint_addr(&ep);
            assert_eq!(buf.len(), ep.encpding_size());

            let (remain, decoded) = be_endpoint_addr(&buf).unwrap();
            assert!(remain.is_empty());
            assert_eq!(decoded, ep);
        }
    }

    #[test]
    fn endpoint_signature_roundtrip_and_verify() {
        #[derive(Debug)]
        struct Ed25519Key(Arc<ring::signature::Ed25519KeyPair>);

        #[derive(Debug)]
        struct Ed25519Signer(Arc<ring::signature::Ed25519KeyPair>);

        impl Signer for Ed25519Signer {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
                Ok(self.0.sign(message).as_ref().to_vec())
            }

            fn scheme(&self) -> SignatureScheme {
                SignatureScheme::ED25519
            }
        }

        impl SigningKey for Ed25519Key {
            fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
                offered
                    .contains(&SignatureScheme::ED25519)
                    .then(|| Box::new(Ed25519Signer(self.0.clone())) as Box<dyn Signer>)
            }

            fn algorithm(&self) -> rustls::SignatureAlgorithm {
                rustls::SignatureAlgorithm::ED25519
            }
        }

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair =
            Arc::new(ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap());
        let key = Ed25519Key(keypair.clone());

        let mut spki = Vec::with_capacity(44);
        spki.extend_from_slice(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]);
        spki.extend_from_slice(keypair.public_key().as_ref());

        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353);
        let mut ep = EndpointAddr::direct_v4(addr);
        ep.set_main(true);
        ep.sign_with(&key, SignatureScheme::ED25519).unwrap();

        let mut buf = BytesMut::new();
        buf.put_endpoint_addr(&ep);
        assert_eq!(buf.len(), ep.encpding_size());

        let (remain, decoded) = be_endpoint_addr(&buf).unwrap();
        assert!(remain.is_empty());
        assert!(decoded.is_signed());
        assert!(decoded.signature().is_some());
        assert!(
            decoded
                .verify_signature(SubjectPublicKeyInfoDer::from(spki.as_slice()))
                .unwrap()
        );

        let mut tampered = decoded.clone();
        tampered.set_main(false);
        assert!(
            !tampered
                .verify_signature(SubjectPublicKeyInfoDer::from(spki.as_slice()))
                .unwrap()
        );
    }
}
