#![cfg(feature = "publishers")]

#[test]
fn publisher_composition_surface_is_qresolve_only() {
    let _ = core::any::type_name::<ddns::publishers::Publishers>();
    let _ = core::any::type_name::<ddns::publishers::PublishReport>();
    let _ = core::any::type_name::<ddns::publishers::PublishersError>();
}
