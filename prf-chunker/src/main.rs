#![deny(elided_lifetimes_in_paths)]
mod chunker;
mod chunkmaker;

use std::fs::File;
use std::io::BufReader;
use clap::Parser;

use chunker::{PHTEChunker, PHTEChunkerNoAES};

use crate::chunkmaker::{Chunk, ChunkMaker};

// Change here the number of runs for each file
const N_RUNS: u32 = 10;

#[derive(Parser, Debug)]
struct Args {
    /// The directory where the datasets are located
    #[clap(long, default_value = "dataset")]
    dataset: String,
}

fn main() {
    let master_key = [0u8; 32];

    let args = Args::parse();

    // read all files in the datasets directory
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&args.dataset).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() && entry.file_name().to_str().unwrap().ends_with(".bin"){
            files.push(entry.path());
        }
    }

    // Sort files by size
    files.sort_by_key(|f| f.metadata().unwrap().len());

    println!("\n[Running chunker with PHTEChunker]\n");

    for f in &files {
        let file = f.file_name().unwrap().to_str().unwrap();
        let callback = Box::new(move |_chunk: Chunk| {
            // Here do something with the chunk, if needed
            // println!("{}", chunk);
            // chunks.push(chunk);
        });

        println!("File: {}", file);

        let mut elapsed = std::time::Duration::new(0, 0);

        for run in 0..(N_RUNS+1) {
            let reader = BufReader::new(File::open(f).unwrap());
            let mut chunker = ChunkMaker::<_, PHTEChunker>::new(&master_key, reader, callback.clone());

            if run == 0 {
                // Warmup
                chunker.chunkify().unwrap();
                continue;
            }

            let start = std::time::Instant::now();
            chunker.chunkify().unwrap();

            let end = std::time::Instant::now();
            elapsed += end - start;

            println!("[{}] Time elapsed: {:?}", file, end - start);
        }

        println!("[{}] Average time elapsed: {:?}", file, elapsed / N_RUNS);
    }

    println!("\n[Running chunker with PHTEChunker - No AES]\n");

    for f in &files {
        let file = f.file_name().unwrap().to_str().unwrap();
        let callback = Box::new(move |_chunk: Chunk| {
            // Here do something with the chunk, if needed
            // println!("{}", chunk);
            // chunks.push(chunk);
        });

        println!("File: {}", file);

        let mut elapsed = std::time::Duration::new(0, 0);

        for run in 0..(N_RUNS+1) {
            let reader = BufReader::new(File::open(f).unwrap());
            let mut chunker = ChunkMaker::<_, PHTEChunkerNoAES>::new(&master_key, reader, callback.clone());

            if run == 0 {
                // Warmup
                chunker.chunkify().unwrap();
                continue;
            }

            let start = std::time::Instant::now();
            chunker.chunkify().unwrap();

            let end = std::time::Instant::now();
            elapsed += end - start;

            println!("[{}] Time elapsed: {:?}", file, end - start);
        }

        println!("[{}] Average time elapsed: {:?}", file, elapsed / N_RUNS);
    }
}
