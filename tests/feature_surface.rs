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

#[cfg(all(feature = "http", feature = "resolvers"))]
#[test]
fn http_backend_is_reexported_from_resolver_facade() {
    use ddns::{http::HttpResolver, resolvers::HttpResolver as FacadeHttpResolver};

    let _ = core::any::type_name::<HttpResolver>();
    let _ = core::any::type_name::<FacadeHttpResolver>();
}

#[cfg(all(feature = "mdns", feature = "resolvers"))]
#[test]
fn mdns_backends_are_reexported_from_resolver_facade() {
    use ddns::{
        mdns::{MdnsBinding, MdnsResolver, MdnsResolverSet},
        resolvers::{
            MdnsBinding as FacadeMdnsBinding, MdnsResolver as FacadeMdnsResolver,
            MdnsResolverSet as FacadeMdnsResolverSet,
        },
    };

    let _ = core::any::type_name::<MdnsResolver>();
    let _ = core::any::type_name::<MdnsBinding>();
    let _ = core::any::type_name::<MdnsResolverSet>();
    let _ = core::any::type_name::<FacadeMdnsResolver>();
    let _ = core::any::type_name::<FacadeMdnsBinding>();
    let _ = core::any::type_name::<FacadeMdnsResolverSet>();
}
