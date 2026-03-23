/*! scure-starknet - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { Field, invert, mod, validateField, type IField } from '@noble/curves/abstract/modular.js';
import { poseidon } from '@noble/curves/abstract/poseidon.js';
import {
  DER,
  ecdsa,
  weierstrass,
  type ECDSASignature,
  type ECDSASignatureCons,
  type WeierstrassPoint,
  type WeierstrassPointCons,
} from '@noble/curves/abstract/weierstrass.js';
import * as u from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

type Hex = Uint8Array | string;
type PrivKey = Hex | bigint;

// Stark-friendly elliptic curve
// https://docs.starkware.co/starkex/stark-curve.html

type _Point = WeierstrassPoint<bigint>;
const CURVE_ORDER = /* @__PURE__ */ BigInt(
  '3618502788666131213697322783095070105526743751716087489154079457884512865583'
);
// 2**251, limit for msgHash and Signature.r
/** Upper bound for Stark message hashes and `Signature.r` values. */
export const MAX_VALUE: bigint = /* @__PURE__ */ BigInt(
  '0x800000000000000000000000000000000000000000000000000000000000000'
);

const nBitLength = 252;
function bits2int(bytes: Uint8Array): bigint {
  while (bytes[0] === 0) bytes = bytes.subarray(1); // strip leading 0s
  // Copy-pasted from weierstrass.ts
  const delta = bytes.length * 8 - nBitLength;
  const num = u.bytesToNumberBE(bytes);
  return delta > 0 ? num >> BigInt(delta) : num;
}
function hex0xToBytes(hex: string): Uint8Array {
  if (typeof hex === 'string') {
    hex = strip0x(hex); // allow 0x prefix
    if (hex.length & 1) hex = '0' + hex; // allow unpadded hex
  }
  return u.hexToBytes(hex);
}

const STARK_CURVE = /* @__PURE__ */ (() => ({
  a: BigInt(1), // Params: a, b
  b: BigInt('3141592653589793238462643383279502884197169399375105820974944592307816406665'),
  // Field over which we'll do calculations; 2n**251n + 17n * 2n**192n + 1n
  // There is no efficient sqrt for field (P%4==1)
  p: BigInt('0x800000000000011000000000000000000000000000000000000000000000001'),
  n: CURVE_ORDER, // Curve order, total count of valid points in the field.
  // nBitLength, // len(bin(N).replace('0b',''))
  // Base point (x, y) aka generator point
  Gx: BigInt('874739451078007766457464989774322083649278607533249481151382481072868806602'),
  Gy: BigInt('152666792071518830868575557812948353041420400780739481342941381225525861407'),
  h: BigInt(1), // cofactor
}))();

const STARK_ECDSA = {
  lowS: false, // Allow high-s signatures
  // Custom truncation routines for stark curve
  bits2int,
  bits2int_modN: (bytes: Uint8Array): bigint => {
    // 2102820b232636d200cb21f1d330f20d096cae09d1bf3edb1cc333ddee11318 =>
    // 2102820b232636d200cb21f1d330f20d096cae09d1bf3edb1cc333ddee113180
    const hex = u.bytesToNumberBE(bytes).toString(16); // toHex unpadded
    if (hex.length === 63) bytes = hex0xToBytes(hex + '0'); // append trailing 0
    return mod(bits2int(bytes), CURVE_ORDER);
  },
};

/**
 * Stark-friendly short Weierstrass point constructor.
 * @example
 * Reach for the curve point constructor when you need low-level Stark curve math.
 * ```ts
 * Point.BASE.toBytes(true);
 * ```
 */
const Point: WeierstrassPointCons<bigint> = /* @__PURE__ */ (() => weierstrass(STARK_CURVE))();
const ECDSA = /* @__PURE__ */ (() => ecdsa(Point, sha256, STARK_ECDSA))();

function toBytes(hex: Hex): Uint8Array {
  return typeof hex === 'string' ? u.hexToBytes(hex) : hex;
}

function toBytesPriv(hex: PrivKey): Uint8Array {
  return typeof hex === 'bigint' ? Point.Fn.toBytes(hex) : toBytes(hex);
}

function ensureBytes(hex: Hex): Uint8Array {
  return u.abytes(typeof hex === 'string' ? hex0xToBytes(hex) : hex);
}

/**
 * Normalizes a Stark private key into a 32-byte lowercase hex string without `0x`.
 * @param privKey - private key as bytes or hex
 * @returns Zero-padded private key hex.
 * @example
 * Normalize a short hex string into the canonical 32-byte Stark private key form.
 * ```ts
 * normalizePrivateKey('1');
 * ```
 */
export function normalizePrivateKey(privKey: Hex): string {
  return u.bytesToHex(ensureBytes(privKey)).padStart(64, '0');
}
/**
 * Derives a Stark public key from a private key.
 * @param privKey - private key as bytes or hex
 * @param isCompressed - whether to return the compressed public key format
 * @returns Encoded Stark public key bytes.
 * @example
 * Derive the Stark public key from a private key.
 * ```ts
 * getPublicKey('1');
 * ```
 */
export function getPublicKey(privKey: Hex, isCompressed = false): Uint8Array {
  return ECDSA.getPublicKey(u.hexToBytes(normalizePrivateKey(privKey)), isCompressed);
}
/**
 * Computes the Stark ECDH shared secret for a private key and peer public key.
 * @param privKeyA - local private key as bytes or hex
 * @param pubKeyB - peer public key as bytes or hex
 * @returns Shared secret bytes.
 * @example
 * Compute the shared secret from one private key and the peer public key.
 * ```ts
 * import { getPublicKey, getSharedSecret } from '@scure/starknet';
 * getSharedSecret('1', getPublicKey('2'));
 * ```
 */
export function getSharedSecret(privKeyA: Hex, pubKeyB: Hex): Uint8Array {
  return ECDSA.getSharedSecret(u.hexToBytes(normalizePrivateKey(privKeyA)), toBytes(pubKeyB));
}

function checkSignature(signature: ECDSASignature) {
  // Signature.s checked inside weierstrass
  const { r, s } = signature;
  if (r < 0n || r >= MAX_VALUE) throw new RangeError(`Signature.r should be [1, ${MAX_VALUE})`);
  const w = invert(s, CURVE_ORDER);
  if (w < 0n || w >= MAX_VALUE)
    throw new RangeError(`inv(Signature.s) should be [1, ${MAX_VALUE})`);
}

function checkMessage(msgHash: Hex) {
  const bytes = ensureBytes(msgHash);
  const num = u.bytesToNumberBE(bytes);
  // num < 0 impossible here
  if (num >= MAX_VALUE) throw new RangeError(`msgHash should be [0, ${MAX_VALUE})`);
  return bytes;
}

/**
 * Signs a Stark message hash without prehashing it first.
 * @param msgHash - message hash inside the Stark field range
 * @param privKey - private key as bytes or hex
 * @param opts - Optional ECDSA signing overrides forwarded to noble-curves.
 * @returns Parsed Stark ECDSA signature.
 * @throws On Stark message hashes or signature values outside the Stark field range. {@link RangeError}
 * @example
 * Sign a prehashed Stark message with a private key.
 * ```ts
 * sign('1', '2');
 * ```
 */
export function sign(msgHash: Hex, privKey: Hex, opts?: any): ECDSASignature {
  const sigBytes = ECDSA.sign(checkMessage(msgHash), u.hexToBytes(normalizePrivateKey(privKey)), {
    prehash: false,
    ...opts,
  });
  const sig = Signature.fromBytes(sigBytes);
  checkSignature(sig);
  return sig;
}

/**
 * Verifies a Stark signature against a message hash and public key.
 * @param signature - signature object or encoded signature bytes/hex
 * @param msgHash - message hash inside the Stark field range
 * @param pubKey - public key as bytes or hex
 * @returns Whether the signature is valid for the message hash.
 * @throws On Stark message hashes or signature values outside the Stark field range. {@link RangeError}
 * @example
 * Verify a Stark signature against the message hash and public key.
 * ```ts
 * import { getPublicKey, sign, verify } from '@scure/starknet';
 * const msgHash = '1';
 * const privKey = '2';
 * verify(sign(msgHash, privKey), msgHash, getPublicKey(privKey));
 * ```
 */
export function verify(signature: ECDSASignature | Hex, msgHash: Hex, pubKey: Hex): boolean {
  if (!(signature instanceof Signature)) {
    const bytes = ensureBytes(signature);
    try {
      signature = Signature.fromBytes(bytes, 'der');
    } catch (derError) {
      if (!(derError instanceof DER.Err)) throw derError;
      signature = Signature.fromBytes(bytes, 'compact');
    }
  }
  checkSignature(signature);
  return ECDSA.verify(signature.toBytes(), checkMessage(msgHash), ensureBytes(pubKey), {
    prehash: false,
  });
}

/**
 * Stark ECDSA signature constructor and byte decoders.
 * @example
 * Construct a Stark signature object and serialize it back to hex.
 * ```ts
 * new Signature(1n, 2n).toHex();
 * ```
 */
const Signature: ECDSASignatureCons = /* @__PURE__ */ (() => ECDSA.Signature)();
/**
 * Helper methods for Stark private keys and point precomputation.
 * @example
 * Check whether a candidate private key lies in the Stark scalar field.
 * ```ts
 * utils.isValidPrivateKey('01');
 * ```
 */
const utils: {
  normPrivateKeyToScalar: (key: PrivKey) => bigint;
  isValidPrivateKey(privateKey: PrivKey): boolean;
  randomPrivateKey: () => Uint8Array;
  precompute: (windowSize?: number, point?: WeierstrassPoint<bigint>) => WeierstrassPoint<bigint>;
} = /* @__PURE__ */ (() => ({
  normPrivateKeyToScalar: (key: PrivKey): bigint => {
    const bytes = toBytesPriv(key);
    const scalar = Point.Fn.fromBytes(bytes);
    if (!Point.Fn.isValidNot0(scalar)) throw new RangeError('wrong secret scalar');
    return scalar;
  },
  isValidPrivateKey: (key) => ECDSA.utils.isValidSecretKey(toBytesPriv(key)),
  randomPrivateKey: ECDSA.utils.randomSecretKey,
  precompute(windowSize = 8, point = Point.BASE) {
    point.precompute(windowSize, false);
    return point;
  },
}))();
export { Point, Signature, utils };

function extractX(bytes: Uint8Array): string {
  const hex = u.bytesToHex(bytes.subarray(1));
  const stripped = hex.replace(/^0+/gm, ''); // strip leading 0s
  return `0x${stripped}`;
}
function strip0x(hex: string) {
  return hex.replace(/^0x/i, '');
}

// seed generation
/**
 * Derives a Stark private key from arbitrary seed material with rejection sampling.
 * @param seed - seed bytes or hex
 * @returns Hex private key suitable for Stark signatures.
 * @throws If rejection sampling does not find a valid Stark private key within the retry limit. {@link Error}
 * @example
 * Grind arbitrary seed material into a Stark private key.
 * ```ts
 * grindKey('01');
 * ```
 */
export function grindKey(seed: Hex): string {
  const _seed = ensureBytes(seed);
  const sha256mask = 2n ** 256n;
  const limit = sha256mask - mod(sha256mask, CURVE_ORDER);
  for (let i = 0; ; i++) {
    const key = sha256Num(u.concatBytes(_seed, u.numberToVarBytesBE(BigInt(i))));
    if (key < limit) return mod(key, CURVE_ORDER).toString(16); // key should be in [0, limit)
    if (i === 100000) throw new Error('grindKey is broken: tried 100k vals'); // prevent dos
  }
}

/**
 * Derives the Stark key x-coordinate for a private key.
 * @param privateKey - private key as bytes or hex
 * @returns Stark key hex string with `0x` prefix.
 * @example
 * Extract the Stark public key x-coordinate as a hex string.
 * ```ts
 * getStarkKey('1');
 * ```
 */
export function getStarkKey(privateKey: Hex): string {
  return extractX(getPublicKey(privateKey, true));
}

/**
 * Turns a 65-byte Ethereum signature into a Stark private key.
 * @param signature - Ethereum signature hex with `0x` prefix
 * @returns Stark private key hex.
 * @throws If grinding the Ethereum signature fails to produce a Stark private key within the retry limit. {@link Error}
 * @throws On wrong Ethereum signature length. {@link RangeError}
 * @example
 * Convert an Ethereum signature into deterministic Stark key material.
 * ```ts
 * ethSigToPrivate(
 *   '0x21fbf0696d5e0aa2ef41a2b4ffb623bcaf070461d61cf7251c74161f82fec3a43' +
 *     '70854bc0a34b3ab487c1bc021cd318c734c51ae29374f2beb0e6f2dd49b4bf41c'
 * );
 * ```
 */
export function ethSigToPrivate(signature: string): string {
  signature = strip0x(signature);
  if (signature.length !== 130) throw new RangeError('Wrong ethereum signature');
  return grindKey(signature.substring(0, 64));
}

const MASK_31 = /* @__PURE__ */ (() => 2n ** 31n - 1n)();
const int31 = (n: bigint) => Number(n & MASK_31);
/**
 * Builds the StarkEx account derivation path for a layer, application, address, and index.
 * @param layer - StarkEx layer name
 * @param application - StarkEx application name
 * @param ethereumAddress - Ethereum address used in derivation
 * @param index - account index inside the derived subtree
 * @returns BIP32 derivation path string.
 * @example
 * Derive the StarkEx account path for one wallet and account index.
 * ```ts
 * getAccountPath('starkex', 'starkdeployement', '0x1', 0);
 * ```
 */
export function getAccountPath(
  layer: string,
  application: string,
  ethereumAddress: string,
  index: number
): string {
  const layerNum = int31(sha256Num(utf8ToBytes(layer)));
  const applicationNum = int31(sha256Num(utf8ToBytes(application)));
  const eth = u.hexToNumber(strip0x(ethereumAddress));
  return `m/2645'/${layerNum}'/${applicationNum}'/${int31(eth)}'/${int31(eth >> 31n)}'/${index}`;
}

// The Pedersen hash uses five different points on the curve.
// This is critical to ensure that they have been generated in a way
// that nobody knows the discrete logarithm of one point regarding another.
//
// Starknet utilizes nothing-up-my-sleeve technique:
// The parameters of the Pedersen hash are generated from the constant 𝜋.
// The x-coordinate of each point is a chunk of 76 decimal digit of 𝜋 modulo 𝑝.
// If it is a quadratic residue then the point is valid
// else the x-coordinate coordinate is incremented by one.
// https://docs.starkware.co/starkex/pedersen-hash-function.html
// https://github.com/starkware-libs/starkex-for-spot-trading/blob/607f0b4ce507e1d95cd018d206a2797f6ba4aab4/src/starkware/crypto/starkware/crypto/signature/nothing_up_my_sleeve_gen.py
const PEDERSEN_POINTS = /* @__PURE__ */ (() =>
  [
    new Point(
      2089986280348253421170679821480865132823066470938446095505822317253594081284n,
      1713931329540660377023406109199410414810705867260802078187082345529207694986n,
      1n
    ),
    new Point(
      996781205833008774514500082376783249102396023663454813447423147977397232763n,
      1668503676786377725805489344771023921079126552019160156920634619255970485781n,
      1n
    ),
    new Point(
      2251563274489750535117886426533222435294046428347329203627021249169616184184n,
      1798716007562728905295480679789526322175868328062420237419143593021674992973n,
      1n
    ),
    new Point(
      2138414695194151160943305727036575959195309218611738193261179310511854807447n,
      113410276730064486255102093846540133784865286929052426931474106396135072156n,
      1n
    ),
    new Point(
      2379962749567351885752724891227938183011949129833673362440656643086021394946n,
      776496453633298175483985398648758586525933812536653089401905292063708816422n,
      1n
    ),
  ] as const)();

function pedersenPrecompute(p1: _Point, p2: _Point): _Point[] {
  const out: _Point[] = [];
  let p = p1;
  for (let i = 0; i < 248; i++) {
    out.push(p);
    p = p.double();
  }
  // NOTE: we cannot use wNAF here, because last 4 bits will require full 248 bits multiplication
  // We can add support for this to wNAF, but it will complicate wNAF.
  p = p2;
  for (let i = 0; i < 4; i++) {
    out.push(p);
    p = p.double();
  }
  return out;
}
const PEDERSEN_POINTS1 = /* @__PURE__ */ (() =>
  pedersenPrecompute(PEDERSEN_POINTS[1], PEDERSEN_POINTS[2]))();
const PEDERSEN_POINTS2 = /* @__PURE__ */ (() =>
  pedersenPrecompute(PEDERSEN_POINTS[3], PEDERSEN_POINTS[4]))();

type PedersenArg = Hex | bigint | number;
function pedersenArg(arg: PedersenArg): bigint {
  let value: bigint;
  if (typeof arg === 'bigint') {
    value = arg;
  } else if (typeof arg === 'number') {
    if (!Number.isSafeInteger(arg)) throw new RangeError(`Invalid pedersenArg: ${arg}`);
    value = BigInt(arg);
  } else {
    value = u.bytesToNumberBE(ensureBytes(arg));
  }
  if (!(0n <= value && value < Point.Fp.ORDER))
    throw new RangeError(`PedersenArg should be 0 <= value < CURVE.P: ${value}`); // [0..Fp)
  return value;
}

/** Warning: Not algorithmic constant-time. */
function pedersenSingle(point: _Point, value: PedersenArg, constants: _Point[]) {
  let x = pedersenArg(value);
  for (let j = 0; j < 252; j++) {
    const pt = constants[j];
    if (!pt) throw new Error('invalid constant index');
    if (pt.equals(point)) throw new Error('Same point');
    if ((x & 1n) !== 0n) point = point.add(pt);
    x >>= 1n;
  }
  return point;
}

// shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
/**
 * Computes the Starknet Pedersen hash of two field elements.
 * @param x - first field element as bytes, hex, bigint, or safe integer
 * @param y - second field element as bytes, hex, bigint, or safe integer
 * @returns Pedersen hash as `0x`-prefixed hex.
 * @throws If Pedersen point encoding fails unexpectedly. {@link Error}
 * @throws On Pedersen inputs outside the Stark field range. {@link RangeError}
 * @example
 * Compute the Pedersen hash of two Stark field elements.
 * ```ts
 * pedersen(1, 2);
 * ```
 */
export function pedersen(x: PedersenArg, y: PedersenArg): string {
  let point: _Point = PEDERSEN_POINTS[0];
  point = pedersenSingle(point, x, PEDERSEN_POINTS1);
  point = pedersenSingle(point, y, PEDERSEN_POINTS2);
  return extractX(point.toBytes(true));
}

// Same as hashChain, but computes hash even for single element and order is not revesed
/**
 * Hashes a list of elements with Pedersen while preserving input order and appending the length.
 * @param data - elements to hash
 * @param fn - hash function used for each fold step
 * @returns Folded hash result.
 * @example
 * Hash an ordered list of elements with the Starknet Pedersen fold.
 * ```ts
 * computeHashOnElements([1, 2, 3]);
 * ```
 */
export const computeHashOnElements = (
  data: PedersenArg[],
  fn: typeof pedersen = pedersen
): PedersenArg => [0, ...data, data.length].reduce((x, y) => fn(x, y));

const MASK_250 = /* @__PURE__ */ u.bitMask(250);
/**
 * Computes Starknet keccak by truncating Keccak-256 to 250 bits.
 * @param data - bytes to hash
 * @returns Hash as a bigint field element.
 * @example
 * Compute Starknet keccak for raw bytes.
 * ```ts
 * keccak(new Uint8Array([1, 2, 3]));
 * ```
 */
export const keccak = (data: Uint8Array): bigint => u.bytesToNumberBE(keccak_256(data)) & MASK_250;
const sha256Num = (data: Uint8Array): bigint => u.bytesToNumberBE(sha256(data));

// Poseidon hash
// Unused for now
// export const Fp253 = Field(
//   BigInt('14474011154664525231415395255581126252639794253786371766033694892385558855681')
// ); // 2^253 + 2^199 + 1
/**
 * Prime field used by Starknet Poseidon: `2^251 + 17 * 2^192 + 1`.
 * @example
 * Construct one field element in the Starknet Poseidon field.
 * ```ts
 * Fp251.create(1n);
 * ```
 */
export const Fp251: Readonly<IField<bigint> & Required<Pick<IField<bigint>, 'isOdd'>>> =
  /* @__PURE__ */ (() =>
    Field(
      BigInt('3618502788666131213697322783095070105623107215331596699973092056135872020481')
    ))(); // 2^251 + 17 * 2^192 + 1

function poseidonRoundConstant(Fp: IField<bigint>, name: string, idx: number) {
  const val = Fp.fromBytes(sha256(utf8ToBytes(`${name}${idx}`)), true);
  return Fp.create(val);
}

const validatePoseidonOpts = (opts: PoseidonOpts) => {
  if (typeof opts.rate !== 'number')
    throw new TypeError(`Wrong poseidon rate: expected number, got ${typeof opts.rate}`);
  if (typeof opts.capacity !== 'number')
    throw new TypeError(`Wrong poseidon capacity: expected number, got ${typeof opts.capacity}`);
  if (typeof opts.roundsFull !== 'number')
    throw new TypeError(
      `Wrong poseidon roundsFull: expected number, got ${typeof opts.roundsFull}`
    );
  if (typeof opts.roundsPartial !== 'number')
    throw new TypeError(
      `Wrong poseidon roundsPartial: expected number, got ${typeof opts.roundsPartial}`
    );
  if (
    !Number.isSafeInteger(opts.rate) ||
    !Number.isSafeInteger(opts.capacity) ||
    !Number.isSafeInteger(opts.roundsFull) ||
    !Number.isSafeInteger(opts.roundsPartial) ||
    opts.rate <= 0 ||
    opts.capacity <= 0 ||
    opts.roundsFull < 0 ||
    opts.roundsPartial < 0
  )
    throw new RangeError(`Wrong poseidon opts: ${opts}`);
};

// NOTE: doesn't check eiginvalues and possible can create unsafe matrix. But any filtration here will break compatibility with starknet
// Please use only if you really know what you doing.
// https://eprint.iacr.org/2019/458.pdf Section 2.3 (Avoiding Insecure Matrices)
export function _poseidonMDS(Fp: IField<bigint>, name: string, m: number, attempt = 0): bigint[][] {
  const x_values: bigint[] = [];
  const y_values: bigint[] = [];
  for (let i = 0; i < m; i++) {
    x_values.push(poseidonRoundConstant(Fp, `${name}x`, attempt * m + i));
    y_values.push(poseidonRoundConstant(Fp, `${name}y`, attempt * m + i));
  }
  if (new Set([...x_values, ...y_values]).size !== 2 * m)
    throw new Error('X and Y values are not distinct');
  return x_values.map((x) => y_values.map((y) => Fp.inv(Fp.sub(x, y))));
}

const MDS_SMALL = /* @__PURE__ */ (() =>
  [
    [3, 1, 1],
    [1, -1, 1],
    [1, 1, -2],
  ].map((i) => i.map(BigInt)))();

/** Poseidon permutation configuration. */
export type PoseidonOpts = {
  /** Prime field used by the permutation. */
  Fp: IField<bigint>;
  /** Number of message elements absorbed per permutation. */
  rate: number;
  /** Number of capacity elements reserved for domain separation. */
  capacity: number;
  /** Count of full rounds with a nonlinear layer on every lane. */
  roundsFull: number;
  /** Count of partial rounds with a nonlinear layer on one lane. */
  roundsPartial: number;
};

/** Poseidon permutation instance returned by the Starknet helpers. */
export type PoseidonFn = ReturnType<typeof poseidon> & {
  /** Total permutation width (`rate + capacity`). */
  m: number;
  /** Number of message elements absorbed per permutation. */
  rate: number;
  /** Number of capacity elements reserved for domain separation. */
  capacity: number;
};

/**
 * Creates a Poseidon permutation from explicit parameters and an MDS matrix.
 * @param opts - Poseidon permutation parameters. See {@link PoseidonOpts}.
 * @param mds - MDS matrix used by the permutation
 * @returns Poseidon permutation with Starknet metadata.
 * @throws On wrong Poseidon option types. {@link TypeError}
 * @throws On invalid Poseidon option ranges. {@link RangeError}
 * @example
 * Create a Poseidon permutation from explicit parameters and an MDS matrix.
 * ```ts
 * import { Fp251, poseidonBasic } from '@scure/starknet';
 * poseidonBasic(
 *   { Fp: Fp251, rate: 2, capacity: 1, roundsFull: 8, roundsPartial: 83 },
 *   [
 *     [3n, 1n, 1n],
 *     [1n, -1n, 1n],
 *     [1n, 1n, -2n],
 *   ]
 * );
 * ```
 */
export function poseidonBasic(opts: PoseidonOpts, mds: bigint[][]): PoseidonFn {
  validateField(opts.Fp);
  validatePoseidonOpts(opts);
  const m = opts.rate + opts.capacity;
  const rounds = opts.roundsFull + opts.roundsPartial;
  const roundConstants = [];
  for (let i = 0; i < rounds; i++) {
    const row = [];
    for (let j = 0; j < m; j++) row.push(poseidonRoundConstant(opts.Fp, 'Hades', m * i + j));
    roundConstants.push(row);
  }
  const res: Partial<PoseidonFn> = poseidon({
    ...opts,
    t: m,
    sboxPower: 3,
    reversePartialPowIdx: true, // Why?!
    mds,
    roundConstants,
  });
  res.m = m;
  res.rate = opts.rate;
  res.capacity = opts.capacity;
  return res as PoseidonFn;
}

/**
 * Creates a Starknet-compatible Poseidon permutation from parameters and an MDS attempt index.
 * @param opts - Poseidon permutation parameters. See {@link PoseidonOpts}.
 * @param mdsAttempt - attempt index used to derive the MDS matrix
 * @returns Poseidon permutation with Starknet metadata.
 * @throws If the derived Poseidon MDS matrix is invalid. {@link Error}
 * @throws On wrong Poseidon option or attempt types. {@link TypeError}
 * @throws On invalid Poseidon option or attempt ranges. {@link RangeError}
 * @example
 * Create the default Starknet-compatible Poseidon permutation from parameters alone.
 * ```ts
 * import { Fp251, poseidonCreate } from '@scure/starknet';
 * poseidonCreate({ Fp: Fp251, rate: 2, capacity: 1, roundsFull: 8, roundsPartial: 83 });
 * ```
 */
export function poseidonCreate(opts: PoseidonOpts, mdsAttempt = 0): PoseidonFn {
  validatePoseidonOpts(opts);
  const m = opts.rate + opts.capacity;
  if (typeof mdsAttempt !== 'number')
    throw new TypeError(`Wrong mdsAttempt type: expected number, got ${typeof mdsAttempt}`);
  if (!Number.isSafeInteger(mdsAttempt) || mdsAttempt < 0)
    throw new RangeError(`Wrong mdsAttempt=${mdsAttempt}`);
  return poseidonBasic(opts, _poseidonMDS(opts.Fp, 'HadesMDS', m, mdsAttempt));
}

/**
 * Default Starknet Poseidon permutation.
 * @example
 * Feed the default Starknet permutation into the standard 2-input hash helper.
 * ```ts
 * import { poseidonHash, poseidonSmall } from '@scure/starknet';
 * poseidonHash(1n, 2n, poseidonSmall);
 * ```
 */
export const poseidonSmall: PoseidonFn = /* @__PURE__ */ poseidonBasic(
  { Fp: Fp251, rate: 2, capacity: 1, roundsFull: 8, roundsPartial: 83 },
  MDS_SMALL
);

/**
 * Hashes two field elements with the default Starknet Poseidon permutation.
 * @param x - first field element
 * @param y - second field element
 * @param fn - Poseidon permutation to use
 * @returns Poseidon hash result.
 * @example
 * Hash two field elements with Starknet Poseidon.
 * ```ts
 * poseidonHash(1n, 2n);
 * ```
 */
export function poseidonHash(x: bigint, y: bigint, fn: PoseidonFn = poseidonSmall): bigint {
  return fn([x, y, 2n])[0]!;
}

/**
 * Hashes two byte arrays with Poseidon and returns the encoded bytes.
 * @param x - first byte array
 * @param y - second byte array
 * @param fn - Poseidon permutation to use
 * @returns Poseidon hash encoded as big-endian bytes.
 * @example
 * Hash two byte arrays and return the Poseidon result as bytes.
 * ```ts
 * poseidonHashFunc(new Uint8Array([1]), new Uint8Array([2]));
 * ```
 */
export function poseidonHashFunc(
  x: Uint8Array,
  y: Uint8Array,
  fn: PoseidonFn = poseidonSmall
): Uint8Array {
  return u.numberToVarBytesBE(poseidonHash(u.bytesToNumberBE(x), u.bytesToNumberBE(y), fn));
}

/**
 * Hashes a single field element with Poseidon.
 * @param x - field element to hash
 * @param fn - Poseidon permutation to use
 * @returns Poseidon hash result.
 * @example
 * Hash one field element with Poseidon.
 * ```ts
 * poseidonHashSingle(1n);
 * ```
 */
export function poseidonHashSingle(x: bigint, fn: PoseidonFn = poseidonSmall): bigint {
  return fn([x, 0n, 1n])[0]!;
}

/**
 * Hashes a list of field elements with Poseidon sponge padding.
 * @param values - field elements to hash
 * @param fn - Poseidon permutation to use
 * @returns Poseidon hash result.
 * @throws If the supplied Poseidon permutation returns malformed state. {@link Error}
 * @throws On wrong `values` argument types. {@link TypeError}
 * @example
 * Hash a list of field elements with Poseidon sponge padding.
 * ```ts
 * poseidonHashMany([1n, 2n, 3n]);
 * ```
 */
export function poseidonHashMany(values: bigint[], fn: PoseidonFn = poseidonSmall): bigint {
  const { m, rate } = fn;
  if (!Array.isArray(values)) throw new TypeError('bigint array expected in values');
  const padded = Array.from(values); // copy
  padded.push(1n);
  while (padded.length % rate !== 0) padded.push(0n);
  let state: bigint[] = new Array(m).fill(0n);
  for (let i = 0; i < padded.length; i += rate) {
    for (let j = 0; j < rate; j++) {
      const item = padded[i + j];
      if (typeof item === 'undefined') throw new Error('invalid index');
      if (typeof state[j] === 'undefined') throw new Error('state[j] is undefined');
      state[j] = state[j]! + item;
    }
    state = fn(state);
  }
  return state[0]!;
}
