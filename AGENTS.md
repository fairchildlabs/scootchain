# Repository Guidelines

## Project Structure & Module Organization
- `scootchain.c`: CLI entrypoint and core logic.
- `inc/`: Public headers (e.g., `inc/scootchain.h`).
- `db_wrapper.c/.h`: Optional RocksDB wrapper (not linked by default).
- `third_party/`: Vendored deps — `liboqs` (required) and `rocksdb` (optional).
- Generated artifacts (ignored): `scootchain`, `*.o`, `*.d`, key files (`*.key`), and `wallet.addr`.

## Build, Test, and Development Commands
- `make deps`: Build third‑party libraries (`liboqs`, `rocksdb`).
- `make liboqs` / `make rocksdb`: Build a dependency individually.
- `make`: Build the `scootchain` binary (links `liboqs` statically).
- `make clean`: Remove objects, deps files, and binary.
- `make format`: Format C sources/headers with `astyle` using `.astylerc`.
- Run locally:
  - `./scootchain genkey`
  - `./scootchain genwallet`
  - `./scootchain checkwallet`
  - `./scootchain seedgen word1 word2 ...`
  - `./scootchain child <index>`

## Coding Style & Naming Conventions
- C, Allman braces, 4‑space indent; auto‑format with `make format`.
- Prefer fixed‑width typedefs from `inc/scootchain.h` (e.g., `UINT8`, `UINT64`).
- Functions: lower_snake_case (e.g., `pubkey_to_address`). Types/structs: `scoot_*` prefix.
- Headers live under `inc/`; include via `-Iinc` (see `Makefile`).

## Testing Guidelines
- No top‑level test suite yet. When adding tests:
  - Place C tests under `tests/` as `test_*.c` and add a `make test` target.
  - Cover CLI flows (key gen, wallet create/verify) and checksum/address validation.
  - Keep tests hermetic: do not read real keys; generate temp files.

## Commit & Pull Request Guidelines
- Commits: short imperative summary (e.g., “Update address scheme”), optionally reference PR/issue (e.g., `(#12)`).
- PRs must include:
  - Clear description and rationale; link issues.
  - Build/run steps (`make`, sample `./scootchain` commands) and expected output.
  - Screenshots or logs when CLI behavior changes.
  - Proof of formatting (`make format`) and clean `git diff`.

## Security & Configuration Tips
- Never commit secrets: `private.key`, `public.key`, `wallet.addr` are git‑ignored by default.
- Rebuild deps on toolchain changes: `make deps` (requires `cmake`, a C compiler, and standard build tools).
- RocksDB is optional; enable by uncommenting its line in `LDLIBS` if used.

