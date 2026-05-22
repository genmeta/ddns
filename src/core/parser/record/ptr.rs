use crate::parser::name::{Name, be_name};

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Ptr(Name);

impl Ptr {
    pub fn name(&self) -> &Name {
        &self.0
    }
}

pub fn be_ptr<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], Ptr> {
    let (remain, name) = be_name(input, origin)?;
    Ok((remain, Ptr(name)))
}
