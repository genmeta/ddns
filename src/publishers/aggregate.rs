use std::{error::Error, fmt};

use dhttp_identity::name::Name;
use snafu::Report;

use super::{AddressView, Publisher, PublisherError};

#[derive(Default, Clone, Debug)]
pub struct Publishers {
    publishers: Vec<Publisher>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherSuccess {
    publisher: String,
}

impl PublisherSuccess {
    pub fn new(publisher: impl Into<String>) -> Self {
        Self {
            publisher: publisher.into(),
        }
    }
}

impl fmt::Display for PublisherSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.publisher)
    }
}

#[derive(Debug)]
pub struct PublishReport {
    successes: Vec<PublisherSuccess>,
    failures: Vec<(String, PublisherError)>,
}

impl PublishReport {
    pub fn successes(&self) -> &[PublisherSuccess] {
        &self.successes
    }

    pub fn failures(&self) -> &[(String, PublisherError)] {
        &self.failures
    }

    pub fn is_complete(&self) -> bool {
        !self.successes.is_empty() && self.failures.is_empty()
    }

    pub fn is_partial(&self) -> bool {
        !self.successes.is_empty() && !self.failures.is_empty()
    }
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

fn format_failures(
    f: &mut fmt::Formatter<'_>,
    heading: &str,
    failures: &[(String, PublisherError)],
) -> fmt::Result {
    write!(f, "{heading}")?;
    for (publisher, error) in failures {
        write!(f, "\n  - {publisher}: {error}")?;
        format_error_sources(f, error)?;
    }
    Ok(())
}

impl fmt::Display for PublishReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.failures.is_empty() {
            let mut successes = self.successes.iter();
            if let Some(first) = successes.next() {
                write!(f, "{first}")?;
                for success in successes {
                    write!(f, "\n{success}")?;
                }
            }
            return Ok(());
        }

        format_failures(f, "some DNS publishers failed", &self.failures)
    }
}

impl fmt::Display for PublishersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return write!(f, "no DNS publishers available");
        }

        format_failures(f, "all DNS publishers failed", &self.errors)
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
    ) -> Result<PublishReport, PublishersError>
    where
        V: AddressView + Sync,
    {
        if self.publishers.is_empty() {
            return Err(PublishersError { errors: Vec::new() });
        }

        let mut successes = Vec::new();
        let mut errors = Vec::new();
        for publisher in &self.publishers {
            match publisher.publish(name, view).await {
                Ok(()) => successes.push(PublisherSuccess::new(publisher.to_string())),
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

        if successes.is_empty() {
            Err(PublishersError { errors })
        } else {
            Ok(PublishReport {
                successes,
                failures: errors,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt, io, sync::Arc};

    use dhttp_identity::name::Name;
    use dquic::qresolve::{EndpointAddr, Publish, PublishFuture};
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
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let _endpoints: Vec<_> = endpoints.collect();
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
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let _endpoints: Vec<_> = endpoints.collect();
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
            .publish(&name(), &view)
            .await
            .expect_err("empty aggregate should fail");

        assert_eq!(error.to_string(), "no DNS publishers available");
    }

    #[tokio::test]
    async fn publishers_report_partial_failure_when_some_publishers_fail() {
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

        let report = publishers
            .publish(&name(), &view)
            .await
            .expect("one success creates partial report");

        assert!(report.is_partial());
        assert_eq!(report.successes().len(), 1);
        assert_eq!(report.failures().len(), 1);
        assert_eq!(
            report.to_string(),
            concat!(
                "some DNS publishers failed\n",
                "  - first publisher: failed to publish dns records with first publisher\n",
                "    1. offline"
            )
        );
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
            .publish(&name(), &view)
            .await
            .expect_err("all publishers fail");

        assert_eq!(
            error.to_string(),
            concat!(
                "all DNS publishers failed\n",
                "  - first publisher: failed to publish dns records with first publisher\n",
                "    1. offline\n",
                "  - second publisher: failed to publish dns records with second publisher\n",
                "    1. permission denied"
            )
        );
    }
}
