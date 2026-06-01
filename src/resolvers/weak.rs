use std::{
    fmt, io,
    sync::{Arc, Weak},
};

use dquic::qresolve::{Publish, PublishFuture, RecordStream, Resolve, ResolveFuture};
use futures::FutureExt;
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum WeakLookupError {
    #[snafu(display("weak resolver target has been dropped"))]
    Dropped,
    #[snafu(display("weak resolver lookup failed"))]
    Lookup { source: io::Error },
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum WeakPublishError {
    #[snafu(display("weak resolver target has been dropped"))]
    Dropped,
    #[snafu(display("weak resolver publish failed"))]
    Publish { source: io::Error },
}

pub struct WeakResolver<R: ?Sized> {
    inner: Weak<R>,
}

impl<R: ?Sized> fmt::Debug for WeakResolver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeakResolver")
            .field("alive", &self.inner.strong_count().gt(&0))
            .finish()
    }
}

impl<R: ?Sized> Clone for WeakResolver<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<R: ?Sized> WeakResolver<R> {
    #[must_use]
    pub fn new(inner: Weak<R>) -> Self {
        Self { inner }
    }

    pub fn upgrade(&self) -> Result<Arc<R>, WeakLookupError> {
        self.inner.upgrade().ok_or(WeakLookupError::Dropped)
    }
}

impl<R: ?Sized> fmt::Display for WeakResolver<R>
where
    R: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.upgrade() {
            Some(resolver) => write!(f, "WeakResolver({resolver})"),
            None => f.write_str("WeakResolver(dropped)"),
        }
    }
}

impl<R: ?Sized> WeakResolver<R>
where
    R: Resolve + 'static,
{
    pub async fn lookup_typed(&self, name: &str) -> Result<RecordStream, WeakLookupError> {
        let resolver = self.upgrade()?;
        resolver
            .lookup(name)
            .await
            .context(weak_lookup_error::LookupSnafu)
    }
}

impl<R: ?Sized> Resolve for WeakResolver<R>
where
    R: Resolve + 'static,
{
    fn lookup<'a>(&'a self, name: &'a str) -> ResolveFuture<'a> {
        async move { self.lookup_typed(name).await.map_err(io::Error::other) }.boxed()
    }
}

impl<R: ?Sized> WeakResolver<R>
where
    R: Publish + 'static,
{
    pub async fn publish_typed(&self, name: &str, packet: &[u8]) -> Result<(), WeakPublishError> {
        let Some(resolver) = self.inner.upgrade() else {
            return weak_publish_error::DroppedSnafu.fail();
        };
        resolver
            .publish(name, packet)
            .await
            .context(weak_publish_error::PublishSnafu)
    }
}

impl<R: ?Sized> Publish for WeakResolver<R>
where
    R: Publish + 'static,
{
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
        async move {
            self.publish_typed(name, packet)
                .await
                .map_err(io::Error::other)
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt, sync::Arc};

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
    async fn lookup_after_target_drop_returns_typed_error() {
        let strong = Arc::new(TestResolver);
        let resolver = WeakResolver::new(Arc::downgrade(&strong));
        drop(strong);

        let error = match resolver.lookup_typed("example.test").await {
            Ok(_) => panic!("dropped weak resolver must not resolve"),
            Err(error) => error,
        };

        assert!(matches!(error, WeakLookupError::Dropped));
    }

    #[tokio::test]
    async fn lookup_forwards_while_target_is_alive() {
        let strong = Arc::new(TestResolver);
        let resolver = WeakResolver::new(Arc::downgrade(&strong));

        let mut stream = resolver.lookup_typed("example.test").await.unwrap();
        let (_source, endpoint) = stream.next().await.expect("forwarded endpoint");

        assert_eq!(
            endpoint,
            EndpointAddr::direct("127.0.0.1:4433".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn publish_forwards_while_target_is_alive() {
        let strong = Arc::new(TestResolver);
        let resolver = WeakResolver::new(Arc::downgrade(&strong));

        resolver
            .publish_typed("example.test", b"packet")
            .await
            .unwrap();
    }
}
