#[cfg(feature = "h3")]
#[test]
fn h3_backend_module_is_public() {
    #[allow(unused_imports)]
    use ddns::h3;
}

#[cfg(feature = "http")]
#[test]
fn http_backend_module_is_public() {
    #[allow(unused_imports)]
    use ddns::http;
}

#[cfg(feature = "mdns")]
#[test]
fn mdns_module_is_public() {
    #[allow(unused_imports)]
    use ddns::mdns;
}

#[test]
fn resolvers_module_is_public() {
    #[allow(unused_imports)]
    use ddns::resolvers;
}

#[test]
fn publishers_module_is_public() {
    #[allow(unused_imports)]
    use ddns::publishers;
}

#[cfg(all(feature = "http", feature = "resolvers", feature = "publishers"))]
#[test]
fn http_backend_is_reexported_from_both_facades() {
    use ddns::{
        http::HttpResolver, publishers::HttpPublisher,
        resolvers::HttpResolver as FacadeHttpResolver,
    };

    let _ = core::any::type_name::<HttpResolver>();
    let _ = core::any::type_name::<HttpPublisher>();
    let _ = core::any::type_name::<FacadeHttpResolver>();
}

#[cfg(all(feature = "mdns", feature = "resolvers", feature = "publishers"))]
#[test]
fn mdns_backend_is_reexported_from_both_facades() {
    use ddns::{
        mdns::MdnsResolver, publishers::MdnsPublisher,
        resolvers::MdnsResolver as FacadeMdnsResolver,
    };

    let _ = core::any::type_name::<MdnsResolver>();
    let _ = core::any::type_name::<MdnsPublisher>();
    let _ = core::any::type_name::<FacadeMdnsResolver>();
}
