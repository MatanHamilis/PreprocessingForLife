use ciborium::{de::from_reader, ser::into_writer};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

pub struct Communicator<T: Write + Read> {
    io: IoCounter<T>,
}

pub struct IoCounter<S: Write + Read> {
    io: S,
    total_bytes_write: usize,
    total_bytes_read: usize,
}

impl<S: Write + Read> From<S> for IoCounter<S> {
    fn from(s: S) -> Self {
        Self {
            io: s,
            total_bytes_read: 0,
            total_bytes_write: 0,
        }
    }
}
impl<S: Write + Read> Write for IoCounter<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let res = self.io.write(buf);
        if let Ok(u) = res {
            self.total_bytes_write += u;
        };
        res
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        let res = self.io.write_vectored(bufs);
        if let Ok(u) = res {
            self.total_bytes_write += u;
        };
        res
    }
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let res = self.io.write_all(buf);
        if let Ok(()) = res {
            self.total_bytes_write += buf.len();
        }
        res
    }
}

impl<S: Write + Read> Read for IoCounter<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.io.read(buf);
        if let Ok(u) = res {
            self.total_bytes_read += u;
        }
        res
    }
    fn read_vectored(&mut self, bufs: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
        let res = self.io.read_vectored(bufs);
        if let Ok(u) = res {
            self.total_bytes_read += u;
        }
        res
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        let res = self.io.read_to_end(buf);
        if let Ok(u) = res {
            self.total_bytes_read += u;
        }
        res
    }
    fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
        let res = self.io.read_to_string(buf);
        if let Ok(u) = res {
            self.total_bytes_read += u;
        }
        res
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let res = self.io.read_exact(buf);
        if let Ok(_) = res {
            self.total_bytes_read += buf.len();
        }
        res
    }
}

impl<S: Read + Write> IoCounter<S> {
    pub fn total_bytes_read(&self) -> usize {
        self.total_bytes_read
    }
    pub fn total_bytes_write(&self) -> usize {
        self.total_bytes_write
    }
}

impl<T: Write + Read> Communicator<T> {
    pub fn exchange<S: Serialize + DeserializeOwned>(&mut self, obj: S) -> Option<S> {
        into_writer(&obj, &mut self.io)
            .ok()
            .and_then(|_| from_reader(&mut self.io).ok())
    }
    pub fn send<S: Serialize + DeserializeOwned>(&mut self, obj: S) -> Option<()> {
        into_writer(&obj, &mut self.io).ok()
    }
    pub fn receive<S: Serialize + DeserializeOwned>(&mut self) -> Option<S> {
        from_reader(&mut self.io).ok()
    }
}

impl<T: Read + Write> From<T> for Communicator<T> {
    fn from(io: T) -> Self {
        Self {
            io: IoCounter::from(io),
        }
    }
}

impl<T: Read + Write> Communicator<T> {
    pub fn total_bytes_read(&self) -> usize {
        self.io.total_bytes_read()
    }
    pub fn total_byte_write(&self) -> usize {
        self.io.total_bytes_write()
    }
}
