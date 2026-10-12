use std::{error::Error, fmt, io, sync::Arc};

use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use qresolve::{EndpointAddr, Publish, PublishFuture};

type ArcPublisher = Arc<dyn Publish>;

#[derive(Clone, Default)]
pub struct Publishers {
    publishers: Vec<ArcPublisher>,
}

impl fmt::Debug for Publishers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.publishers.iter().map(ToString::to_string))
            .finish()
    }
}

impl fmt::Display for Publishers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Publishers(")?;
        for (index, publisher) in self.publishers.iter().enumerate() {
            if index != 0 {
                f.write_str(", ")?;
            }
            fmt::Display::fmt(publisher, f)?;
        }
        f.write_str(")")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherSuccess(String);

impl PublisherSuccess {
    #[must_use]
    pub fn publisher(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublisherSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub struct PublishReport {
    successes: Vec<PublisherSuccess>,
    failures: Vec<(String, io::Error)>,
}

impl PublishReport {
    #[must_use]
    pub fn successes(&self) -> &[PublisherSuccess] {
        &self.successes
    }

    #[must_use]
    pub fn failures(&self) -> &[(String, io::Error)] {
        &self.failures
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }

    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.successes.is_empty() && !self.failures.is_empty()
    }
}

impl fmt::Display for PublishReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.failures.is_empty() {
            return write!(f, "{} DNS publisher(s) succeeded", self.successes.len());
        }
        format_failures(f, "some DNS publishers failed", &self.failures)
    }
}

#[derive(Debug)]
pub struct PublishersError {
    errors: Vec<(String, io::Error)>,
}

impl PublishersError {
    #[must_use]
    pub fn errors(&self) -> &[(String, io::Error)] {
        &self.errors
    }
}

impl fmt::Display for PublishersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            f.write_str("no DNS publishers available")
        } else {
            format_failures(f, "all DNS publishers failed", &self.errors)
        }
    }
}

impl Error for PublishersError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors.first().map(|(_, error)| error as _)
    }
}

fn format_failures(
    f: &mut fmt::Formatter<'_>,
    heading: &str,
    failures: &[(String, io::Error)],
) -> fmt::Result {
    f.write_str(heading)?;
    for (publisher, error) in failures {
        write!(f, "\n  - {publisher}: {error}")?;
        let mut source = error.source();
        let mut index = 1;
        while let Some(error) = source {
            write!(f, "\n    {index}. {error}")?;
            source = error.source();
            index += 1;
        }
    }
    Ok(())
}

impl Publishers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, publisher: ArcPublisher) -> Self {
        self.push(publisher);
        self
    }

    pub fn push(&mut self, publisher: ArcPublisher) {
        self.publishers.push(publisher);
    }

    pub async fn publish_all(
        &self,
        name: &str,
        endpoints: impl IntoIterator<Item = EndpointAddr>,
    ) -> Result<PublishReport, PublishersError> {
        if self.publishers.is_empty() {
            return Err(PublishersError { errors: Vec::new() });
        }

        let endpoints: Arc<[EndpointAddr]> = endpoints.into_iter().collect();
        let name: Arc<str> = name.into();
        let pending = self
            .publishers
            .iter()
            .cloned()
            .map(|publisher| {
                let endpoints = endpoints.clone();
                let name = name.clone();
                async move {
                    let label = publisher.to_string();
                    let mut endpoints = endpoints.iter().copied();
                    (label, publisher.publish(&name, &mut endpoints).await)
                }
            })
            .collect::<FuturesUnordered<_>>();

        let results = pending.collect::<Vec<_>>().await;
        let mut successes = Vec::new();
        let mut failures = Vec::new();
        for (label, result) in results {
            match result {
                Ok(()) => successes.push(PublisherSuccess(label)),
                Err(error) => failures.push((label, error)),
            }
        }

        if successes.is_empty() {
            Err(PublishersError { errors: failures })
        } else {
            Ok(PublishReport {
                successes,
                failures,
            })
        }
    }
}

impl Publish for Publishers {
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &mut dyn Iterator<Item = EndpointAddr>,
    ) -> PublishFuture<'a> {
        let endpoints = endpoints.collect::<Vec<_>>();
        async move {
            let report = self
                .publish_all(name, endpoints)
                .await
                .map_err(io::Error::other)?;
            for (publisher, error) in report.failures() {
                tracing::debug!(%publisher, %error, "DNS publisher failed");
            }
            Ok(())
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestPublisher(&'static str, bool);

    impl fmt::Display for TestPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Publish for TestPublisher {
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let count = endpoints.count();
            async move {
                if self.1 && count == 1 {
                    Ok(())
                } else {
                    Err(io::Error::other("failed"))
                }
            }
            .boxed()
        }
    }

    #[tokio::test]
    async fn fans_out_one_snapshot_and_reports_partial_failure() {
        let publishers = Publishers::new()
            .with(Arc::new(TestPublisher("ok", true)))
            .with(Arc::new(TestPublisher("bad", false)));
        let report = publishers
            .publish_all(
                "demo.dhttp.net",
                [EndpointAddr::direct("192.0.2.1:443".parse().unwrap())],
            )
            .await
            .unwrap();

        assert!(report.is_partial());
        assert_eq!(report.successes().len(), 1);
        assert_eq!(report.failures().len(), 1);
    }
}
