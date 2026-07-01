use std::{error::Error, fmt};

use dhttp_identity::{certificate::CertificateChainKey, name::Name};
use snafu::Report;

use super::{AddressView, Publisher, PublisherError};

#[derive(Default, Clone, Debug)]
pub struct Publishers {
    publishers: Vec<Publisher>,
}

#[derive(Debug)]
pub struct PublishersError {
    errors: Vec<(String, PublisherError)>,
}

fn format_error_sources(f: &mut fmt::Formatter<'_>, error: &(dyn Error + 'static)) -> fmt::Result {
    let mut index = 1;
    let mut current = error.source();

    while let Some(source) = current {
        write!(f, "\n    {index}. {source}")?;
        index += 1;
        current = source.source();
    }

    Ok(())
}

impl fmt::Display for PublishersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return write!(f, "no DNS publishers available");
        }

        write!(f, "all DNS publishers failed")?;
        for (publisher, error) in &self.errors {
            write!(f, "\n  - {publisher}: {error}")?;
            format_error_sources(f, error)?;
        }
        Ok(())
    }
}

impl Error for PublishersError {}

impl Publishers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, publisher: Publisher) -> Self {
        self.push(publisher);
        self
    }

    pub fn push(&mut self, publisher: Publisher) {
        self.publishers.push(publisher);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Publisher> {
        self.publishers.iter()
    }

    pub async fn publish<V>(
        &self,
        name: &Name<'_>,
        view: &V,
        chain_key: Option<&CertificateChainKey>,
    ) -> Result<(), PublishersError>
    where
        V: AddressView + Sync,
    {
        if self.publishers.is_empty() {
            return Err(PublishersError { errors: Vec::new() });
        }

        let mut errors = Vec::new();
        let mut succeeded = false;
        for publisher in &self.publishers {
            match publisher.publish(name, view, chain_key).await {
                Ok(()) => succeeded = true,
                Err(error) => {
                    let publisher_name = publisher.to_string();
                    let report = Report::from_error(&error);
                    tracing::debug!(
                        publisher = %publisher_name,
                        error = %report,
                        name = %name,
                        "dns publisher failed"
                    );
                    errors.push((publisher_name, error));
                }
            }
        }

        if succeeded {
            Ok(())
        } else {
            Err(PublishersError { errors })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt, io, sync::Arc};

    use dhttp_identity::name::Name;
    use dquic::qresolve::{Publish, PublishFuture};
    use futures::FutureExt;

    use crate::publishers::{PublishScope, Publisher, Publishers};

    #[derive(Debug)]
    struct OkPublisher(&'static str);

    impl fmt::Display for OkPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Publish for OkPublisher {
        fn publish<'a>(&'a self, _name: &'a str, _packet: &'a [u8]) -> PublishFuture<'a> {
            async move { Ok(()) }.boxed()
        }
    }

    #[derive(Debug)]
    struct ErrPublisher(&'static str, &'static str);

    impl fmt::Display for ErrPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Publish for ErrPublisher {
        fn publish<'a>(&'a self, _name: &'a str, _packet: &'a [u8]) -> PublishFuture<'a> {
            let message = self.1;
            async move { Err(io::Error::other(message)) }.boxed()
        }
    }

    fn name() -> Name<'static> {
        Name::try_from("alice.dhttp.net").expect("valid name")
    }

    #[tokio::test]
    async fn empty_publishers_report_no_publishers_available() {
        let publishers = Publishers::new();
        let view = crate::publishers::PublishAddresses::new();

        let error = publishers
            .publish(&name(), &view, None)
            .await
            .expect_err("empty aggregate should fail");

        assert_eq!(error.to_string(), "no DNS publishers available");
    }

    #[tokio::test]
    async fn publishers_succeed_when_any_publisher_succeeds() {
        let publishers = Publishers::new()
            .with(Publisher::new(
                PublishScope::WideArea,
                Arc::new(ErrPublisher("first publisher", "offline")),
            ))
            .with(Publisher::new(
                PublishScope::WideArea,
                Arc::new(OkPublisher("second publisher")),
            ));
        let view = crate::publishers::PublishAddresses::new();

        publishers
            .publish(&name(), &view, None)
            .await
            .expect("one success is enough");
    }

    #[tokio::test]
    async fn publishers_report_all_failures_when_every_publisher_fails() {
        let publishers = Publishers::new()
            .with(Publisher::new(
                PublishScope::WideArea,
                Arc::new(ErrPublisher("first publisher", "offline")),
            ))
            .with(Publisher::new(
                PublishScope::WideArea,
                Arc::new(ErrPublisher("second publisher", "permission denied")),
            ));
        let view = crate::publishers::PublishAddresses::new();

        let error = publishers
            .publish(&name(), &view, None)
            .await
            .expect_err("all publishers fail");

        assert_eq!(
            error.to_string(),
            concat!(
                "all DNS publishers failed\n",
                "  - first publisher: failed to publish dns packet with first publisher\n",
                "    1. offline\n",
                "  - second publisher: failed to publish dns packet with second publisher\n",
                "    1. permission denied"
            )
        );
    }
}
