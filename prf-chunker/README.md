# PRF Chunker

Note that we are using the SIMD version of the bytemuck crate.

## Benchmarking

Generate the random datasets

```bash
cd datasets
make
```

Compile the chunker and run it

```bash
cargo build --release
./target/release/prf_chunker
```
