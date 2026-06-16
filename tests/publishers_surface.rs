#[cfg(feature = "publishers")]
#[test]
fn publishers_facade_exposes_publisher_and_aggregate_types() {
    let _ = core::any::type_name::<ddns::publishers::Publisher>();
    let _ = core::any::type_name::<ddns::publishers::Publishers>();
    let _ = core::any::type_name::<ddns::publishers::PublisherError>();
    let _ = core::any::type_name::<ddns::publishers::PublishersError>();
    let _ = core::any::type_name::<ddns::publishers::PublishScope>();
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
#[test]
fn publishers_facade_exposes_network_publication_loop_surface() {
    let _ = ddns::publishers::DEFAULT_PUBLISH_INTERVAL;
    let _ = ddns::publishers::DEFAULT_PUBLISH_TIMEOUT;
    let _ = core::any::type_name::<
        ddns::publishers::EndpointPublicationLoop<ddns::publishers::EndpointBindingAddresses>,
    >();
}
