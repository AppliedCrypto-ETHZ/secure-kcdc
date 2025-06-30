use crate::chunker::FSWChunker;
use anyhow::Result;
use std::{
    fmt::Display,
    io::{BufReader, Read},
};

const BUFFER_SIZE: usize = 1024 * 1024;
const MIN_CHUNK_SIZE: usize = 512 * 1024;
const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;

pub struct Chunk {
    index: usize,
    data: Vec<u8>,
}

impl Chunk {
    fn new(index: usize, data: &mut Vec<u8>) -> Self {
        let mut new_vec = Vec::new();
        std::mem::swap(&mut new_vec, data);
        Self {
            index,
            data: new_vec,
        }
    }
}

impl Display for Chunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Chunk at position {} with {} bytes",
            self.index,
            self.data.len()
        )
    }
}

pub struct ChunkMaker<R: Read, C: FSWChunker> {
    reader: BufReader<R>,
    callback: Box<dyn FnMut(Chunk)>,
    chunker: C,
}

impl<R: Read, C: FSWChunker> ChunkMaker<R, C> {
    pub fn new(master_key: &[u8; 32], reader: R, callback: Box<dyn FnMut(Chunk)>) -> Self {
        Self {
            chunker: C::new(master_key),
            reader: BufReader::with_capacity(BUFFER_SIZE, reader),
            callback,
        }
    }

    pub fn chunkify(&mut self) -> Result<()> {
        let mut buf = [0u8; BUFFER_SIZE];
        let mut chunk_data = Vec::new();
        let mut index: usize = 0;
        let mut buf_start: usize = 0;
        let min_chunk = MIN_CHUNK_SIZE - C::window_size();

        loop {
            let mut size = match self.reader.read(&mut buf[buf_start..]) {
                Ok(size) => buf_start + size,
                Err(e) => {
                    eprintln!("Error reading from input: {}", e);
                    break;
                }
            };

            // In general, buf_start will always be 0, except when we have leftover
            // data that we read while creating the previous chunk.
            // After reading, this does not matter anymore, so we reset it to 0.
            buf_start = 0;

            // EOF reached, return what we have as a chunk and exit
            if size == 0 {
                // eprintln!("EOF reached");
                if !chunk_data.is_empty() {
                    (self.callback)(Chunk::new(index, &mut chunk_data));
                }
                break;
            }

            // Check if we reached the minimum chunk size
            let len = chunk_data.len();

            if len < min_chunk {
                // Do we have enough data to reach the minimum chunk size now?
                if len + size >= min_chunk {
                    // Insert that much data into the chunk
                    // and move onto hashing
                    let remaining = min_chunk - len;
                    chunk_data
                        .extend_from_slice(&buf[..remaining + C::window_size() - 1]);
                    index += remaining;

                    // Update the hasher to include the entirety of the window
                    for i in 0..C::window_size() - 1 {
                        self.chunker.update(buf[remaining + i]);
                    }

                    // Move the remaining data to the beginning of the buffer
                    buf.copy_within(remaining + C::window_size() - 1..size, 0);
                    size -= remaining;
                } else {
                    // Not enough data yet, copy the entire buffer
                    // and do not start hashing
                    chunk_data.extend_from_slice(&buf[..size]);
                    index += size;
                    continue;
                }
            }

            // Invariant: chunk_data has at least MIN_CHUNK_SIZE - 1 bytes (because 1 byte is going
            // to be added in the loop below and evaluated to see whether we should have a chunk
            // which is exactly MIN_CHUNK_SIZE bytes long)

            let mut chunk_found: bool = false;

            for i in 0..size {
                index += 1;

                // See if we need to chunk here
                self.chunker.update(buf[i]);

                if chunk_data.len() + i + 1 == MAX_CHUNK_SIZE || self.chunker.eval() {
                    // Copy the data to the chunk
                    chunk_data.extend_from_slice(&buf[..i + 1]);

                    // Process the chunk
                    chunk_found = true;
                    (self.callback)(Chunk::new(index, &mut chunk_data));
                    self.chunker.reset();

                    // Move the spillover data to the beginning of the buffer and set the
                    // buf_start accordingly so that the next read does not overwrite
                    buf.copy_within(i + 1..size, 0);
                    buf_start = size - (i + 1);

                    break;
                }
            }

            if !chunk_found {
                // We have not reached a chunk boundary yet
                // Copy the entire buffer to the chunk data
                chunk_data.extend_from_slice(&buf[..size]);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_chunkify() {
        let master_key = [0u8; 32];

        let mut data = Vec::with_capacity(1024 * 1024 * 10);
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        rng.fill(&mut data[..]);

        let mut chunks: Vec<Chunk> = Vec::new();

        let callback = Box::new(move |chunk: Chunk| {
            println!("{}", chunk);
            chunks.push(chunk);
        });

        let reader = std::io::Cursor::new(&data);

        let mut chunker = ChunkMaker::new(&master_key, reader, callback);
        chunker.chunkify().unwrap();
    }
}
