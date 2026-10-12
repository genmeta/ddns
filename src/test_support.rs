use qtls::LocalAuthority;

pub(crate) fn authority(name: &str, sequence: u8, kind_flag: u8) -> LocalAuthority {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    let ski = format!("{sequence}:{kind_flag}:{}", "0123456789abcdef".repeat(4));
    let mut extension = vec![0x04, ski.len() as u8];
    extension.extend_from_slice(ski.as_bytes());
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 14],
            extension,
        ));
    let cert = params.self_signed(&key).unwrap();
    LocalAuthority::new(
        &qtls::default_provider(),
        name.into(),
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        b"test-ocsp".to_vec(),
    )
    .unwrap()
}
