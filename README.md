# Poly-Hashing-then-Encrypt + Patched Restic Chunker Benchmarking

The following artefact contains code for our implementation of the Poly-Hashing-then-Encrypt chunker (as described in the paper) and a patched version of the Restic chunker that applies AES encryption to the output of the rolling hash function. This allows us to compare the performance of both chunkers on the same datasets.

The results of running these chunkers are shown in Fig. 5 of the associated paper.

## Generating the random datasets

To generate the random datasets, navigate to the `datasets` directory in both the `prf-chunker` and `restic-chunker` folders) and run the following command:

```bash
cd datasets
make
```

This will create files of increasing sizes (up to 16 GB) by reading from `/dev/random`. These are the files which will be chunked by the chunkers.
If you want to use the datasets from the `prf-chunker` folder, you can symlink them to the `restic-chunker` folder:

## Poly-Hashing-then-Encrypt Chunker

This chunker implementation is written in Rust (version 1.81.0) and, as such, it requires the Rust toolchain to compile and run. The chunker uses SIMD optimizations via the `bytemuck` crate for performance improvements. Results may differ on systems which do not support SIMD.

To compile and run the chunker, execute the following commands:

```bash
cargo build --release
./target/release/prf_chunker
```

This will automatically print one run of the chunker on each dataset, including the time taken.

## Patched Restic Chunker

This chunker is implemented in Go (version 1.24.1) and applies AES encryption to the output of the rolling hash function.

To run the patched Restic chunker, ensure you have Go installed and then execute the following command:

```bash
go run main.go
```

This will automatically print one run of the chunker on each dataset, including the time taken.
