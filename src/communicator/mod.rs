use ciborium::{de::from_reader, ser::into_writer};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

pub struct Communicator<T: Write + Read> {
    io: T,
}

impl<T: Write + Read> Communicator<T> {
    pub fn exchange<S: Serialize + DeserializeOwned>(&mut self, obj: S) -> Option<S> {
        into_writer(&obj, &mut self.io)
            .ok()
            .and_then(|_| from_reader(&mut self.io).ok())
    }
}

impl<T: Read + Write> From<T> for Communicator<T> {
    fn from(io: T) -> Self {
        Self { io }
    }
}
