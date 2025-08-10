# scure-starknet

Audited & minimal JS implementation of Starknet cryptography.

- 🔒 [Audited](#security) by an independent security firm
- 🧜‍♂️ [Stark curve](https://docs.starkware.co/starkex/stark-curve.html), pedersen and poseidon hashes
- ➰ Uses [noble-curves](https://github.com/paulmillr/noble-curves) for underlying arithmetics

### This library belongs to _scure_

> **scure** — audited micro-libraries.

- Zero or minimal dependencies
- Highly readable TypeScript / JS code
- PGP-signed releases and transparent NPM builds
- Check out [homepage](https://paulmillr.com/noble/#scure) & all libraries:
  [base](https://github.com/paulmillr/scure-base),
  [bip32](https://github.com/paulmillr/scure-bip32),
  [bip39](https://github.com/paulmillr/scure-bip39),
  [btc-signer](https://github.com/paulmillr/scure-btc-signer),
  [sr25519](https://github.com/paulmillr/scure-sr25519),
  [starknet](https://github.com/paulmillr/scure-starknet)

## Usage

> `npm install @scure/starknet`

> `jsr add jsr:@scure/starknet`

```ts
import * as starknet from '@scure/starknet';
```

We support all major platforms and runtimes.

Note: the examples use the 'deepStrictEqual' function from the 'assert' built-in NodeJS module to compare values.

In Typescript, you must first install the '@types/node' npm package and then import like this: `import { deepStrictEqual } from 'assert';`.

In vanilla Javascript, just do this: `const { deepStrictEqual } = require("assert");` <br>

### Curve

```ts
// Signing and verification
const privateKey = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
const publicKey = starknet.getPublicKey(privateKey);
const messageHash = 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47';
const sig = starknet.sign(messageHash, privateKey);
const { r, s } = sig;
deepStrictEqual(r.toString(16), '5f496f6f210b5810b2711c74c15c05244dad43d18ecbbdbe6ed55584bc3b0a2');
deepStrictEqual(s.toString(16), '4e8657b153787f741a67c0666bad6426c3741b478c8eaa3155196fc571416f3');
deepStrictEqual(starknet.verify(sig, messageHash, publicKey), true);

// Private key to StarkKey
deepStrictEqual(
  starknet.getStarkKey('0x178047D3869489C055D7EA54C014FFB834A069C9595186ABE04EA4D1223A03F'),
  '0x1895a6a77ae14e7987b9cb51329a5adfb17bd8e7c638f92d6892d76e51cebcf'
);

// Pedersen hash
deepStrictEqual(
  starknet.pedersen(
    '0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
    '0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a'
  ),
  '30e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662'
);

// Create private key from ethereum signature
const ethSignature =
  '0x21fbf0696d5e0aa2ef41a2b4ffb623bcaf070461d61cf7251c74161f82fec3a43' +
  '70854bc0a34b3ab487c1bc021cd318c734c51ae29374f2beb0e6f2dd49b4bf41c';
deepStrictEqual(
  starknet.ethSigToPrivate(ethSignature),
  '766f11e90cd7c7b43085b56da35c781f8c067ac0d578eabdceebc4886435bda'
);
```

### Private key from mnemonic

```ts
import * as bip32 from '@scure/bip32';
import * as bip39 from '@scure/bip39';

should('Seed derivation (example)', () => {
  const layer = 'starknet';
  const application = 'starkdeployement';
  const mnemonic =
    'range mountain blast problem vibrant void vivid doctor cluster enough melody ' +
    'salt layer language laptop boat major space monkey unit glimpse pause change vibrant';
  const ethAddress = '0xa4864d977b944315389d1765ffa7e66F74ee8cd7';
  const hdKey = bip32.HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic)).derive(
    starknet.getAccountPath(layer, application, ethAddress, 0)
  );
  deepStrictEqual(
    starknet.grindKey(hdKey.privateKey),
    '6cf0a8bf113352eb863157a45c5e5567abb34f8d32cddafd2c22aa803f4892c'
  );
});
```

### Poseidon

[Poseidon hash](https://www.poseidon-hash.info) can be used in the following way:

```ts
type PoseidonFn = ReturnType<typeof poseidon> & {
  m: number;
  rate: number;
  capacity: number;
};
function poseidonHash(x: bigint, y: bigint, fn?: PoseidonFn): bigint;
function poseidonHashFunc(x: Uint8Array, y: Uint8Array, fn?: PoseidonFn): Uint8Array;
function poseidonHashSingle(x: bigint, fn?: PoseidonFn): bigint;
function poseidonHashMany(values: bigint[], fn?: PoseidonFn): bigint;
```

### Utils

```ts
// Hash chain
deepStrictEqual(
  starknet.hashChain([1, 2, 3]),
  '5d9d62d4040b977c3f8d2389d494e4e89a96a8b45c44b1368f1cc6ec5418915'
);

// Key grinding
deepStrictEqual(
  starknet.grindKey('86F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0519'),
  '5c8c8683596c732541a59e03007b2d30dbbbb873556fe65b5fb63c16688f941'
);

// Starknet keccak
deepStrictEqual(
  starknet.keccak(utf8.decode('hello')),
  0x8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8n
);
```

## Security

The library has been independently audited:

- at version 0.3.0, in Sep 2023, by [Kudelski Security](https://kudelskisecurity.com)
  - PDFs: [offline](./audit/2023-09-kudelski-audit-starknet.pdf)
  - [Changes since audit](https://github.com/paulmillr/scure-starknet/compare/0.3.0..main)
  - Scope: [scure-starknet](https://github.com/paulmillr/scure-starknet) and its related abstract
    modules of noble-curves: `curve`, `modular`, `poseidon`, `weierstrass`
  - The audit has been funded by [Starkware](https://starkware.co)

## Speed

Benchmark results on Apple M2 with node v20:

```
stark
init x 33 ops/sec @ 30ms/op
pedersen
├─old x 86 ops/sec @ 11ms/op # @starkware-industries/starkware-crypto-utils
└─scure x 620 ops/sec @ 1ms/op
poseidon x 7,162 ops/sec @ 139μs/op
verify
├─old x 303 ops/sec @ 3ms/op
└─scure x 485 ops/sec @ 2ms/op
```

## Contributing & testing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests

## Resources

- [Starknet docs](https://docs.starkware.co/starkex/stark-curve.html)
- [SNARK Security and Performance](https://a16zcrypto.com/content/article/snark-security-and-performance/)
  calculating security level of snarks.

## License

The MIT License (MIT)

Copyright (c) 2022 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
