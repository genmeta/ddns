#[cfg(feature = "publishers")]
#[test]
fn publishers_facade_exposes_endpoint_publisher_and_aggregate_types() {
    let _ = core::any::type_name::<ddns::publishers::EndpointPublisher>();
    let _ = core::any::type_name::<
        ddns::publishers::EndpointPublisher<
            dyn dhttp_identity::identity::LocalAuthority + Send + Sync,
            dyn dquic::qresolve::Resolve + Send + Sync,
        >,
    >();

    let _ = core::any::type_name::<ddns::publishers::Publishers>();
    let _ = core::any::type_name::<ddns::publishers::PublishersBuilder>();
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
#[test]
fn publishers_facade_exposes_network_publication_loop_surface() {
    let _ = ddns::publishers::DEFAULT_PUBLISH_INTERVAL;
    let _ = ddns::publishers::DEFAULT_PUBLISH_TIMEOUT;
    let _ = core::any::type_name::<ddns::publishers::CreatePublisherError>();
    let _ = core::any::type_name::<ddns::publishers::PublishOnceError>();
    let _ = core::any::type_name::<ddns::publishers::EndpointPublisherLoop>();
    let _ = core::any::type_name::<
        ddns::publishers::EndpointPublicationLoop<
            dyn dhttp_identity::identity::LocalAuthority + Send + Sync,
            dyn dquic::qresolve::Resolve + Send + Sync,
            ddns::publishers::EndpointBindingAddresses,
        >,
    >();
}
