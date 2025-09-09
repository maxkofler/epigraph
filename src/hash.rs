//! The module that handles hashing for the object database

use std::io::{self, Read, Write};

pub mod sha512;

/// The buffer size used for file operations
pub const BUF_SIZE: usize = 4096;

/// A method that can be used to provide the underlying
/// hashing functionality for the object database
pub trait HashMethod<const S: usize> {
    /// The associated instance of the method
    type Instance: HashMethodInstance<S>;

    /// Create a new instance of the hash function
    /// to hash data in the object database
    fn instantiate(&self) -> Self::Instance;

    /// Returns the unique ID for this hashing method
    fn id() -> u8;

    /// Returns the size of the resulting digest
    fn digest_size() -> usize {
        S
    }

    /// Hashes the contents of a stream until `EOF` is encountered
    /// # Arguments
    /// * `src` - The stream to hash
    /// # Returns
    /// The calculated digest of the stream contents
    fn hash_stream<R: Read>(&self, src: &mut R) -> Result<[u8; S], io::Error> {
        let mut inst = self.instantiate();

        inst.hash_stream(src)?;

        Ok(inst.finalize())
    }

    /// Hashes the contents of a stream until `EOF` is encountered, passing
    /// the data through to another stream in the process
    /// # Arguments
    /// * `src` - The stream to hash
    /// * `dst` - The stream to write the pass-through data to
    /// # Returns
    /// The calculated digest of the stream contents
    fn hash_stream_passthrough<R: Read, W: Write>(
        &self,
        src: &mut R,
        dst: Option<&mut W>,
    ) -> Result<[u8; S], io::Error> {
        let mut inst = self.instantiate();

        inst.hash_stream_passthrough(src, dst)?;

        Ok(inst.finalize())
    }
}

/// An instance of a hashing method
pub trait HashMethodInstance<const S: usize> {
    /// Update the hash with some new data
    /// # Arguments
    /// * `data` - The data to be pushed
    fn update(&mut self, data: &[u8]);

    /// Finalize the
    fn finalize(self) -> [u8; S];

    /// Returns the size of the resulting digest
    fn digest_size() -> usize {
        S
    }

    /// Hashes the contents of a stream until `EOF` is encountered
    /// # Arguments
    /// * `src` - The stream to hash
    /// # Returns
    /// The number of bytes read from the `src` stream
    fn hash_stream<R: Read>(&mut self, src: &mut R) -> Result<usize, io::Error> {
        let mut buf = [0u8; BUF_SIZE];
        let mut stream_len = 0;

        loop {
            let len = src.read(&mut buf)?;

            if len == 0 {
                break;
            }

            self.update(&buf[0..len]);
            stream_len += len;
        }

        Ok(stream_len)
    }

    /// Hashes the contents of a stream until `EOF` is encountered, passing
    /// the data through to another stream in the process
    /// # Arguments
    /// * `src` - The stream to hash
    /// * `dst` - The stream to write the pass-through data to
    /// # Returns
    /// The number of bytes read from the `src` stream
    fn hash_stream_passthrough<R: Read, W: Write>(
        &mut self,
        src: &mut R,
        mut dst: Option<&mut W>,
    ) -> Result<usize, io::Error> {
        let mut buf = [0u8; BUF_SIZE];
        let mut stream_len = 0;

        loop {
            let len = src.read(&mut buf)?;

            if len == 0 {
                break;
            }

            self.update(&buf[0..len]);
            stream_len += len;

            if let Some(dst) = dst.as_mut() {
                dst.write_all(&buf[0..len])?;
            }
        }

        Ok(stream_len)
    }
}
