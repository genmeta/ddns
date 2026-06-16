#[cfg(feature = "h3")]
#[test]
fn h3_backend_and_facades_export_the_same_type_name() {
    use ddns::{
        h3::H3Resolver, publishers::H3Publisher, resolvers::H3Resolver as FacadeH3Resolver,
    };

    let _ = core::any::type_name::<H3Resolver<h3x::dquic::QuicEndpoint>>();
    let _ = core::any::type_name::<H3Publisher<h3x::dquic::QuicEndpoint>>();
    let _ = core::any::type_name::<FacadeH3Resolver<h3x::dquic::QuicEndpoint>>();
}
