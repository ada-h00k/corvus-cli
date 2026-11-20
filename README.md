# corvus-cli

A Signal backend for Corvus, written in Rust and built on
[presage](https://github.com/whisperfish/presage). It implements the command-line interface
and JSON-RPC API expected by Corvus.

Build the project, then select `corvus-cli` in Corvus under
**Settings → Advanced → Choose …**. The backend has its own device link, so the computer
must be linked with the phone again. Existing chat history in Corvus is kept.

## Build

Requirements: Rust 1.85+, `protoc`, clang and cmake (for libsignal's BoringSSL).

```sh
cargo build --release
```

The binary is `target/release/corvus-cli`.

## Arch Linux

Versioned GitHub releases include an installable package:

```sh
sudo pacman -U corvus-cli-<version>-1-x86_64.pkg.tar.zst
```

To build it locally, install `base-devel`, `cargo`, `clang`, `cmake`, `git`,
`openssl`, `protobuf` and `pkgconf`, then run:

```sh
makepkg -si
```

The PKGBUILD uses the matching version tag and locked Cargo dependencies.

## Development dependencies

The project currently uses Corvus integration branches of
[presage](https://github.com/ada-h00k/presage) and
[libsignal-service-rs](https://github.com/ada-h00k/libsignal-service-rs), both on the
`corvus` branch. They contain functionality not yet available upstream and are pinned
through the dependency configuration.

For local development, clone both repositories next to this one. The presage dependency
can be overridden in an uncommitted Cargo config:

```toml
[patch."https://github.com/ada-h00k/presage"]
presage = { path = "../presage/presage" }
presage-store-sqlite = { path = "../presage/presage-store-sqlite" }
```

## Behaviour

- Safety numbers use trust on first use. Changed identity keys must be verified before
  messages are sent; group sends omit untrusted members. Decisions are stored in
  `trust.json`.
- Blocking, message requests and username changes are synchronized through the storage
  service. Messages from blocked contacts and groups are ignored.
- Incoming attachments, link-preview images and stickers are downloaded automatically;
  delivery receipts are sent for received messages.
- Sticker packs are synchronized with the phone. Packs can be installed from a
  `signal.art` link, and stickers can be sent with `sticker: "packId:stickerId"`.
- Link previews are generated only when requested by Corvus.

Data is stored in `$XDG_DATA_HOME/corvus-cli` (or `$CORVUS_CLI_DIR`), with a directory
per account. Set `CORVUS_CLI_LOG` to configure logging; `-v` and `-vv` increase
verbosity.

## Tests

```sh
cargo test
```

To regenerate the JSON contract fixture:

```sh
CORVUS_UPDATE_CONTRACT=1 cargo test
```

Copy the updated `tests/data/corvus-cli-contract.json` into the Corvus repository so
its backend contract test can verify the parser against the new output.
