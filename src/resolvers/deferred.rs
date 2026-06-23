use std::{fmt, io};

use dquic::qresolve::{Publish, PublishFuture, RecordStream, Resolve, ResolveFuture};
use futures::FutureExt;
use snafu::{ResultExt, Snafu};
use tokio::sync::{Notify, OnceCell};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum DeferredLookupError {
    #[snafu(display("deferred resolver has not been initialized"))]
    Uninitialized,
    #[snafu(display("deferred resolver lookup failed"))]
    Lookup { source: io::Error },
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum DeferredPublishError {
    #[snafu(display("deferred resolver has not been initialized"))]
    Uninitialized,
    #[snafu(display("deferred resolver publish failed"))]
    Publish { source: io::Error },
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum SetDeferredResolverError {
    #[snafu(display("deferred resolver has already been initialized"))]
    AlreadyInitialized,
}

pub struct DeferredResolver<R> {
    inner: OnceCell<R>,
    initialized: Notify,
}

impl<R> fmt::Debug for DeferredResolver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeferredResolver")
            .field("initialized", &self.inner.get().is_some())
            .finish()
    }
}

impl<R> Default for DeferredResolver<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> DeferredResolver<R> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OnceCell::new(),
            initialized: Notify::new(),
        }
    }

    pub fn set(&self, resolver: R) -> Result<(), SetDeferredResolverError> {
        if self.inner.set(resolver).is_err() {
            return set_deferred_resolver_error::AlreadyInitializedSnafu.fail();
        }
        self.initialized.notify_waiters();
        Ok(())
    }

    #[must_use]
    pub fn get(&self) -> Option<&R> {
        self.inner.get()
    }

    async fn wait(&self) -> &R {
        loop {
            let initialized = self.initialized.notified();
            if let Some(resolver) = self.get() {
                return resolver;
            }
            initialized.await;
        }
    }
}

impl<R> fmt::Display for DeferredResolver<R>
where
    R: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.get() {
            Some(resolver) => write!(f, "DeferredResolver({resolver})"),
            None => f.write_str("DeferredResolver(uninitialized)"),
        }
    }
}

impl<R> DeferredResolver<R>
where
    R: Resolve + 'static,
{
    pub async fn lookup_typed(&self, name: &str) -> Result<RecordStream, DeferredLookupError> {
        let Some(resolver) = self.get() else {
            return deferred_lookup_error::UninitializedSnafu.fail();
        };
        resolver
            .lookup(name)
            .await
            .context(deferred_lookup_error::LookupSnafu)
    }
}

impl<R> Resolve for DeferredResolver<R>
where
    R: Resolve + 'static,
{
    fn lookup<'a>(&'a self, name: &'a str) -> ResolveFuture<'a> {
        async move { self.wait().await.lookup(name).await }.boxed()
    }
}

impl<R> DeferredResolver<R>
where
    R: Publish + 'static,
{
    pub async fn publish_typed(
        &self,
        name: &str,
        packet: &[u8],
    ) -> Result<(), DeferredPublishError> {
        let Some(resolver) = self.get() else {
            return deferred_publish_error::UninitializedSnafu.fail();
        };
        resolver
            .publish(name, packet)
            .await
            .context(deferred_publish_error::PublishSnafu)
    }
}

impl<R> Publish for DeferredResolver<R>
where
    R: Publish + 'static,
{
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
        async move { self.wait().await.publish(name, packet).await }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt, time::Duration};

    use dquic::{
        qbase::net::addr::EndpointAddr,
        qresolve::{Publish, Resolve, Source},
    };
    use futures::{FutureExt, StreamExt};

    use super::*;

    #[derive(Debug)]
    struct TestResolver;

    impl fmt::Display for TestResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test resolver")
        }
    }

    impl Resolve for TestResolver {
        fn lookup<'a>(&'a self, _name: &'a str) -> dquic::qresolve::ResolveFuture<'a> {
            async move {
                let endpoint = EndpointAddr::direct("127.0.0.1:4433".parse().unwrap());
                Ok(futures::stream::iter([(Source::System, endpoint)]).boxed())
            }
            .boxed()
        }
    }

    impl Publish for TestResolver {
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            _packet: &'a [u8],
        ) -> dquic::qresolve::PublishFuture<'a> {
            async move { Ok(()) }.boxed()
        }
    }

    #[tokio::test]
    async fn lookup_before_set_returns_typed_uninitialized_error() {
        let resolver: DeferredResolver<TestResolver> = DeferredResolver::new();

        let error = match resolver.lookup_typed("example.test").await {
            Ok(_) => panic!("uninitialized resolver must not resolve"),
            Err(error) => error,
        };

        assert!(matches!(error, DeferredLookupError::Uninitialized));
    }

    #[tokio::test]
    async fn resolve_trait_lookup_waits_until_set() {
        let resolver = DeferredResolver::new();
        let mut lookup = resolver.lookup("example.test");

        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut lookup)
                .await
                .is_err(),
            "trait lookup must not fail fast before set"
        );

        resolver.set(TestResolver).expect("first set succeeds");

        let mut stream = lookup.await.expect("lookup completes after set");
        let (_source, endpoint) = stream.next().await.expect("forwarded endpoint");
        assert_eq!(
            endpoint,
            EndpointAddr::direct("127.0.0.1:4433".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn lookup_after_set_forwards_to_inner_resolver() {
        let resolver = DeferredResolver::new();
        resolver.set(TestResolver).expect("first set succeeds");

        let mut stream = resolver.lookup_typed("example.test").await.unwrap();
        let (_source, endpoint) = stream.next().await.expect("forwarded endpoint");

        assert_eq!(
            endpoint,
            EndpointAddr::direct("127.0.0.1:4433".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn publish_after_set_forwards_to_inner_resolver() {
        let resolver = DeferredResolver::new();
        resolver.set(TestResolver).expect("first set succeeds");

        resolver
            .publish_typed("example.test", b"packet")
            .await
            .unwrap();
    }
}
