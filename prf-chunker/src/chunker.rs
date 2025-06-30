use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_crypto::{Aes128Enc, AesEncrypt};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::VecDeque;
use std::convert::From;

use risc0_core::field::{goldilocks::GoldilocksElem, Elem};

pub trait FSWChunker {
    fn new(master_key: &[u8; 32]) -> Self;
    fn reset(&mut self);
    fn update(&mut self, byte: u8);
    fn eval(&self) -> bool;
    fn window_size() -> usize;
}

pub struct PHTEChunkerNoAES {
    // The sliding window of the last window_size() bytes
    window: VecDeque<GoldilocksElem>,

    // The current position in the data stream
    buf_pos: usize,

    // The current state of the polynomial evaluation.
    // We currently use the 64-bit Goldilocks field.
    state: GoldilocksElem,

    // The polynomial hashing key
    poly_key: GoldilocksElem,

    // The value of the polynomial hashing key raised to the power of the window size, which is
    // needed to remove the oldest byte from the state.
    poly_key_power: GoldilocksElem,

    // The mask to apply to the output to get the chunking decision
    mask: u64,
}

impl PHTEChunkerNoAES {
    const WINDOW_SIZE: usize = 64;
    const AVG_CHUNK_SIZE_BITS: usize = 20;
    const POLY_KDF_LABEL: &[u8] = b"chunker-poly-key";
}

impl FSWChunker for PHTEChunkerNoAES {
    fn window_size() -> usize {
        Self::WINDOW_SIZE
    }

    fn new(master_key: &[u8; 32]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, master_key);

        let mut poly_key_raw = [0u8; 8];
        hkdf.expand(Self::POLY_KDF_LABEL, &mut poly_key_raw)
            .expect("Failed to generate poly key");

        // Convert poly_key_raw to GoldilocksElem
        let poly_key = GoldilocksElem::new(u64::from_be_bytes(poly_key_raw));

        let poly_key_power = poly_key.pow(Self::WINDOW_SIZE - 1);

        let mask = (1 << Self::AVG_CHUNK_SIZE_BITS) - 1;

        Self {
            window: VecDeque::with_capacity(Self::WINDOW_SIZE),
            buf_pos: 0,
            state: Elem::ZERO,
            poly_key,
            poly_key_power,
            mask,
        }
    }

    fn reset(&mut self) {
        self.window.clear();
        self.buf_pos = 0;
        self.state = Elem::ZERO;
    }

    fn update(&mut self, byte: u8) {
        // Update the window
        let to_remove = if self.window.len() == Self::WINDOW_SIZE {
            // The check above ensures that this will enver return None
            self.window.pop_front().unwrap()
        } else {
            Elem::ZERO
        };

        let to_add = GoldilocksElem::new(byte as u64);

        self.window.push_back(to_add);

        // Update the state
        self.state = (self.state - to_remove * self.poly_key_power) * self.poly_key
            + GoldilocksElem::from(byte as u64);
    }

    fn eval(&self) -> bool {
        let state_bytes = self.state.to_u32_words();
        let block: &[u8] =
            bytemuck::try_cast_slice(&state_bytes).expect("Failed to cast state to AES block");
        let result = u64::from_be_bytes(block.try_into().unwrap());

        result & self.mask == 0
    }
}

pub struct PHTEChunker {
    // The sliding window of the last window_size() bytes
    window: VecDeque<GoldilocksElem>,

    // The current position in the data stream
    buf_pos: usize,

    // The current state of the polynomial evaluation.
    // We currently use the 64-bit Goldilocks field.
    state: GoldilocksElem,

    // The polynomial hashing key
    poly_key: GoldilocksElem,

    // The value of the polynomial hashing key raised to the power of the window size, which is
    // needed to remove the oldest byte from the state.
    poly_key_power: GoldilocksElem,

    // The AES cipher block instance
    cipher: Aes128,

    // The mask to apply to the AES output to get the chunking decision
    mask: u128,
}

impl PHTEChunker {
    const WINDOW_SIZE: usize = 64;
    const AVG_CHUNK_SIZE_BITS: usize = 20;
    const AES_KDF_LABEL: &[u8] = b"chunker-aes-key";
    const POLY_KDF_LABEL: &[u8] = b"chunker-poly-key";
}

impl FSWChunker for PHTEChunker {
    fn window_size() -> usize {
        Self::WINDOW_SIZE
    }

    fn new(master_key: &[u8; 32]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, master_key);

        let mut aes_key = [0u8; 16];
        hkdf.expand(Self::AES_KDF_LABEL, &mut aes_key)
            .expect("Failed to generate AES key");

        let cipher = Aes128::new(&GenericArray::from(aes_key));

        let mut poly_key_raw = [0u8; 8];
        hkdf.expand(Self::POLY_KDF_LABEL, &mut poly_key_raw)
            .expect("Failed to generate poly key");

        // Convert poly_key_raw to GoldilocksElem
        let poly_key = GoldilocksElem::new(u64::from_be_bytes(poly_key_raw));

        let poly_key_power = poly_key.pow(Self::WINDOW_SIZE - 1);

        let mask = (1 << Self::AVG_CHUNK_SIZE_BITS) - 1;

        Self {
            window: VecDeque::with_capacity(Self::WINDOW_SIZE),
            buf_pos: 0,
            state: Elem::ZERO,
            poly_key,
            poly_key_power,
            cipher,
            mask,
        }
    }

    fn reset(&mut self) {
        self.window.clear();
        self.buf_pos = 0;
        self.state = Elem::ZERO;
    }

    fn update(&mut self, byte: u8) {
        // Update the window
        let to_remove = if self.window.len() == Self::WINDOW_SIZE {
            // The check above ensures that this will enver return None
            self.window.pop_front().unwrap()
        } else {
            Elem::ZERO
        };

        let to_add = GoldilocksElem::new(byte as u64);

        self.window.push_back(to_add);

        // Update the state
        self.state = (self.state - to_remove * self.poly_key_power) * self.poly_key
            + GoldilocksElem::from(byte as u64);
    }

    fn eval(&self) -> bool {
        let state_bytes = self.state.to_u32_words();
        let block: &[u8] =
            bytemuck::try_cast_slice(&state_bytes).expect("Failed to cast state to AES block");
        let mut full_block = [0u8; 16];
        full_block[..block.len()].copy_from_slice(block);
        let mut full_block_copy = GenericArray::from(full_block);
        self.cipher.encrypt_block(&mut full_block_copy);
        let result_bytes: [u8; 16] = full_block_copy.as_slice().try_into().unwrap();
        let result = u128::from_be_bytes(result_bytes);

        result & self.mask == 0
    }
}


pub struct PHTEChunkerAESCrypto {
    // The sliding window of the last window_size() bytes
    window: VecDeque<GoldilocksElem>,

    // The current position in the data stream
    buf_pos: usize,

    // The current state of the polynomial evaluation.
    // We currently use the 64-bit Goldilocks field.
    state: GoldilocksElem,

    // The polynomial hashing key
    poly_key: GoldilocksElem,

    // The value of the polynomial hashing key raised to the power of the window size, which is
    // needed to remove the oldest byte from the state.
    poly_key_power: GoldilocksElem,

    // The AES cipher block instance
    cipher: Aes128Enc,

    // The mask to apply to the AES output to get the chunking decision
    mask: u128,
}

impl PHTEChunkerAESCrypto {
    const WINDOW_SIZE: usize = 64;
    const AVG_CHUNK_SIZE_BITS: usize = 20;
    const AES_KDF_LABEL: &[u8] = b"chunker-aes-key";
    const POLY_KDF_LABEL: &[u8] = b"chunker-poly-key";
}

impl FSWChunker for PHTEChunkerAESCrypto {
    fn window_size() -> usize {
        Self::WINDOW_SIZE
    }

    fn new(master_key: &[u8; 32]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, master_key);

        let mut aes_key = [0u8; 16];
        hkdf.expand(Self::AES_KDF_LABEL, &mut aes_key)
            .expect("Failed to generate AES key");

        // let cipher = Aes128::new(&GenericArray::from(aes_key));
        let cipher = Aes128Enc::from(aes_key);

        let mut poly_key_raw = [0u8; 8];
        hkdf.expand(Self::POLY_KDF_LABEL, &mut poly_key_raw)
            .expect("Failed to generate poly key");

        // Convert poly_key_raw to GoldilocksElem
        let poly_key = GoldilocksElem::new(u64::from_be_bytes(poly_key_raw));

        let poly_key_power = poly_key.pow(Self::WINDOW_SIZE - 1);

        let mask = (1 << Self::AVG_CHUNK_SIZE_BITS) - 1;

        Self {
            window: VecDeque::with_capacity(Self::WINDOW_SIZE),
            buf_pos: 0,
            state: Elem::ZERO,
            poly_key,
            poly_key_power,
            cipher,
            mask,
        }
    }

    fn reset(&mut self) {
        self.window.clear();
        self.buf_pos = 0;
        self.state = Elem::ZERO;
    }

    fn update(&mut self, byte: u8) {
        // Update the window
        let to_remove = if self.window.len() == Self::WINDOW_SIZE {
            // The check above ensures that this will enver return None
            self.window.pop_front().unwrap()
        } else {
            Elem::ZERO
        };

        let to_add = GoldilocksElem::new(byte as u64);

        self.window.push_back(to_add);

        // Update the state
        self.state = (self.state - to_remove * self.poly_key_power) * self.poly_key
            + GoldilocksElem::from(byte as u64);
    }

    fn eval(&self) -> bool {
        let state_bytes = self.state.to_u32_words();
        let block: &[u8] =
            bytemuck::try_cast_slice(&state_bytes).expect("Failed to cast state to AES block");
        let mut full_block = [0u8; 16];
        full_block[..block.len()].copy_from_slice(block);
        let out_block = self.cipher.encrypt_block(full_block.into());
        let result = u128::from_be_bytes(out_block.into());

        result & self.mask == 0
    }
}
