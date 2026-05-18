use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Txt {
    bytes: Vec<u8>,
}

impl Deref for Txt {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Txt {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}
