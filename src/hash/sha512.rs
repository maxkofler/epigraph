use sha2::{Digest, Sha512};

use crate::hash::{HashMethod, HashMethodInstance};

const SIZE: usize = 64;

/// The `SHA512` hashing algorithm
pub struct Sha512Hash {}

impl HashMethod<SIZE> for Sha512Hash {
    type Instance = Sha512Instance;
    fn instantiate(&self) -> Self::Instance {
        Sha512Instance::new()
    }
}

/// An instance of the `SHA512` hashing algorithm
pub struct Sha512Instance {
    hash: Sha512,
}

impl Sha512Instance {
    fn new() -> Self {
        Self {
            hash: Sha512::new(),
        }
    }
}

impl HashMethodInstance<SIZE> for Sha512Instance {
    fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    fn finalize(self) -> [u8; SIZE] {
        self.hash.finalize().into()
    }
}
