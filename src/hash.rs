//! The module that handles hashing for the object database

/// A method that can be used to provide the underlying
/// hashing functionality for the object database
pub trait HashMethod<const S: usize> {
    /// The associated instance of the method
    type Instance: HashMethodInstance<S>;

    /// Create a new instance of the hash function
    /// to hash data in the object database
    fn instantiate(&self) -> Self::Instance;

    /// Returns the size of the resulting digest
    fn digest_size() -> usize {
        S
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
}
