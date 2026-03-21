use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[allow(dead_code)]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    #[allow(dead_code)]
    pub fn secure_zero(&mut self) {
        unsafe {
            // 1. Volatile write - LLVM cannot prove it's dead
            for byte in self.data.iter_mut() {
                core::ptr::write_volatile(byte, 0);
            }
            // 2. Memory barrier - prevents reordering
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            // 3. Black-box the pointer - prevents whole-program DSE
            let _ = core::ptr::read_volatile(&self.data.as_ptr());
        }
        // Fallback to zeroize
        self.data.zeroize();
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.secure_zero();
        self.data.clear();
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Default for SecureBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for SecureBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

// ZeroizeOnDrop will handle the zeroization automatically
// DO NOT implement Drop manually - it would break zeroization
impl ZeroizeOnDrop for SecureBuffer {}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}
