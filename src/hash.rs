//! The module that handles hashing for the object database

use std::{
    io::{self, Read, Write},
    path::PathBuf,
};

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
    fn hash_stream<R: Read>(&self, src: &mut R) -> Result<HashDigest<S>, io::Error> {
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
    ) -> Result<HashDigest<S>, io::Error> {
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
    fn finalize(self) -> HashDigest<S>;

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

/// The result from a hash calculation
pub struct HashDigest<const S: usize> {
    data: [u8; S],
}

impl<const S: usize> HashDigest<S> {
    /// Create a new instance of a hash digest
    /// # Arguments
    /// * `data` - The underlying data of the calculation
    pub fn new(data: [u8; S]) -> Self {
        Self { data }
    }

    /// Returns a hex string representation of this digest
    pub fn to_hex(&self) -> String {
        hex::encode(self.data)
    }

    /// Convert this digest into a path with a certain depth:
    /// - depth = 0 -> `abcd...`
    /// - depth = 1 -> `ab/cd...`
    /// # Arguments
    /// * `depth` - The depth of the path to create
    /// # Returns
    /// A relative path for this digest
    pub fn to_path(&self, depth: usize) -> PathBuf {
        // Cap the depth at the maximum for the digest size
        let depth = if depth < S - 1 { depth } else { S - 1 };

        let mut path = PathBuf::new();
        let string = self.to_hex();
        let mut str_ref = string.as_str();

        for _ in 0..depth {
            let dir = &str_ref[0..2];
            path.push(dir);
            str_ref = &str_ref[2..];
        }

        path.push(str_ref);

        path
    }
}
