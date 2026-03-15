# AckAgent Web SDK

TypeScript SDK for browser-based AckAgent signing request flows. Published as `@ackagent/web-sdk` on npm.

## Install

```sh
npm install @ackagent/web-sdk
```

## Build & Test

```sh
pnpm install
make download-test-vectors  # Fetch cross-platform test vectors
pnpm build
pnpm vitest run
```

## Dependencies

- [@ackagent/api](https://github.com/AckAgent/api) — TypeScript types (npm)
- [ackagent/bbs-ffi](https://github.com/AckAgent/bbs-ffi) — WASM (BBS+ signatures)

## Consumers

- [naughtbot/sdk](https://github.com/naughtbot/sdk) — peer dependency
