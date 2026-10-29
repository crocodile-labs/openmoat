# openmoat-wasm

The WebAssembly module inside the JavaScript SDK (`sdk/js`): `openmoat-sdk` behind a plain
C ABI, one JSON request and answer at a time. It imports nothing, so it cannot reach a
network, a clock or a file. Not published on its own; `scripts/ci/sdk-js.sh` builds it
into the npm package. Part of [OpenMoat](https://github.com/crocodile-labs/openmoat);
see [docs/SDK.md](../../docs/SDK.md) and ADR-046.
