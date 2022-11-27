/*! micro-starkex - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { randomBytes } from '@noble/hashes/utils';

// https://docs.starkware.co/starkex/stark-curve.html
export const CURVE = Object.freeze({
  // Params: a, b
  a: 1n,
  b: 3141592653589793238462643383279502884197169399375105820974944592307816406665n,
  // Field over which we'll do calculations. Verify with:
  // NOTE: there is no efficient sqrt for field (P%4==1)
  P: 2n ** 251n + 17n * 2n ** 192n + 1n,
  // Curve order, total count of valid points in the field. Verify with:
  n: 3618502788666131213697322783095070105526743751716087489154079457884512865583n,
  nBits: 252, // len(bin(N).replace('0b',''))
  // Base point (x, y) aka generator point
  Gx: 874739451078007766457464989774322083649278607533249481151382481072868806602n,
  Gy: 152666792071518830868575557812948353041420400780739481342941381225525861407n,
  // Default options
  signOpts: { canonical: false },
  verifyOpts: { strict: false },
});

/**
 * y² = x³ + ax + b: Short weierstrass curve formula
 * @returns y²
 */
function weierstrass(x: bigint): bigint {
  const { a, b } = CURVE;
  const x2 = mod(x * x);
  const x3 = mod(x2 * x);
  return mod(x3 + a * x + b);
}

// We accept hex strings besides Uint8Array for simplicity
type Bytes = Uint8Array;
type Hex = Uint8Array | string;
// Very few implementations accept numbers, we do it to ease learning curve
type PrivKey = Hex | bigint | number;
// 33/65-byte ECDSA key
type PubKey = Hex | Point;
// ECDSA signature
type Sig = Hex | Signature;

/**
 * Jacobian Point works in 3d / jacobi coordinates: (x, y, z) ∋ (x=x/z², y=y/z³)
 * Default Point works in 2d / affine coordinates: (x, y)
 * We're doing calculations in jacobi, because its operations don't require costly inversion.
 */
class JacobianPoint {
  constructor(readonly x: bigint, readonly y: bigint, readonly z: bigint) {}

  static readonly BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, 1n);
  static readonly ZERO = new JacobianPoint(0n, 1n, 0n);
  static fromAffine(p: Point): JacobianPoint {
    if (!(p instanceof Point)) {
      throw new TypeError('JacobianPoint#fromAffine: expected Point');
    }
    // fromAffine(x:0, y:0) would produce (x:0, y:0, z:1), but we need (x:0, y:1, z:0)
    if (p.equals(Point.ZERO)) return JacobianPoint.ZERO;
    return new JacobianPoint(p.x, p.y, 1n);
  }

  /**
   * Takes a bunch of Jacobian Points but executes only one
   * invert on all of them. invert is very slow operation,
   * so this improves performance massively.
   */
  static toAffineBatch(points: JacobianPoint[]): Point[] {
    const toInv = invertBatch(points.map((p) => p.z));
    return points.map((p, i) => p.toAffine(toInv[i]));
  }

  static normalizeZ(points: JacobianPoint[]): JacobianPoint[] {
    return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
  }

  /**
   * Compare one point to another.
   */
  equals(other: JacobianPoint): boolean {
    if (!(other instanceof JacobianPoint)) throw new TypeError('JacobianPoint expected');
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = other;
    const Z1Z1 = mod(Z1 * Z1);
    const Z2Z2 = mod(Z2 * Z2);
    const U1 = mod(X1 * Z2Z2);
    const U2 = mod(X2 * Z1Z1);
    const S1 = mod(mod(Y1 * Z2) * Z2Z2);
    const S2 = mod(mod(Y2 * Z1) * Z1Z1);
    return U1 === U2 && S1 === S2;
  }

  /**
   * Flips point to one corresponding to (x, -y) in Affine coordinates.
   */
  negate(): JacobianPoint {
    return new JacobianPoint(this.x, mod(-this.y), this.z);
  }

  // Fast algo for doubling 2 Jacobian Points.
  // From: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
  // Cost: 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*8..
  double(): JacobianPoint {
    const { x: X1, y: Y1, z: Z1 } = this;
    const XX = mod(X1 * X1); // XX = X1^2
    const YY = mod(Y1 * Y1); // YY = Y1^2
    const YYYY = mod(YY * YY); // YYYY = YY^2
    const ZZ = mod(Z1 * Z1); // ZZ = Z1^2
    const tmp1 = mod(X1 + YY); // (X1+YY)
    const tmp2 = mod(tmp1 * tmp1); // (X1+YY)^2
    const S = mod(2n * (tmp2 - XX - YYYY)); // 2*((X1+YY)^2-XX-YYYY)
    const ZZZZ = mod(ZZ * ZZ); // ZZ^2
    const M = mod(3n * XX + CURVE.a * ZZZZ); // 3*XX+a*ZZ^2
    const MM = mod(M * M); // M^2
    const T = mod(MM - 2n * S); // M^2-2*S
    const X3 = T;
    const Y3 = mod(M * (S - T) - 8n * YYYY); // M*(S-T)-8*YYYY
    const Y1Z1 = mod(Y1 + Z1); // (Y1+Z1)
    const tmp3 = mod(Y1Z1 * Y1Z1); // (Y1+Z1)^2
    const Z3 = mod(tmp3 - YY - ZZ); // (Y1+Z1)^2-YY-ZZ
    return new JacobianPoint(X3, Y3, Z3);
  }

  // Fast algo for adding 2 Jacobian Points.
  // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-1998-cmo-2
  // Cost: 12M + 4S + 6add + 1*2
  // Note: 2007 Bernstein-Lange (11M + 5S + 9add + 4*2) is actually 10% slower.
  add(other: JacobianPoint): JacobianPoint {
    if (this.equals(JacobianPoint.ZERO)) return other;
    if (!(other instanceof JacobianPoint)) throw new TypeError('JacobianPoint expected');
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = other;
    if (X2 === 0n || Y2 === 0n) return this;
    if (X1 === 0n || Y1 === 0n) return other;
    // We're using same code in equals()
    const Z1Z1 = mod(Z1 * Z1); // Z1Z1 = Z1^2
    const Z2Z2 = mod(Z2 * Z2); // Z2Z2 = Z2^2;
    const U1 = mod(X1 * Z2Z2); // X1 * Z2Z2
    const U2 = mod(X2 * Z1Z1); // X2 * Z1Z1
    const S1 = mod(mod(Y1 * Z2) * Z2Z2); // Y1 * Z2 * Z2Z2
    const S2 = mod(mod(Y2 * Z1) * Z1Z1); // Y2 * Z1 * Z1Z1
    const H = mod(U2 - U1); // H = U2 - U1
    const r = mod(S2 - S1); // S2 - S1
    // H = 0 meaning it's the same point.
    if (H === 0n) {
      if (r === 0n) {
        return this.double();
      } else {
        return JacobianPoint.ZERO;
      }
    }
    const HH = mod(H * H); // HH = H2
    const HHH = mod(H * HH); // HHH = H * HH
    const V = mod(U1 * HH); // V = U1 * HH
    const X3 = mod(r * r - HHH - 2n * V); // X3 = r^2 - HHH - 2 * V;
    const Y3 = mod(r * (V - X3) - S1 * HHH); // Y3 = r * (V - X3) - S1 * HHH;
    const Z3 = mod(Z1 * Z2 * H); // Z3 = Z1 * Z2 * H;
    return new JacobianPoint(X3, Y3, Z3);
  }

  subtract(other: JacobianPoint) {
    return this.add(other.negate());
  }

  /**
   * Non-constant-time multiplication. Uses double-and-add algorithm.
   * It's faster, but should only be used when you don't care about
   * an exposed private key e.g. sig verification, which works over *public* keys.
   */
  multiplyUnsafe(scalar: bigint): JacobianPoint {
    const P0 = JacobianPoint.ZERO;
    if (typeof scalar === 'bigint' && scalar === 0n) return P0;
    // Will throw on 0
    let n = normalizeScalar(scalar);
    if (n === 1n) return this;
    let p = P0;
    let d: JacobianPoint = this;
    while (n > 0n) {
      if (n & 1n) p = p.add(d);
      d = d.double();
      n >>= 1n;
    }
    return p;
  }

  /**
   * Creates a wNAF precomputation window. Used for caching.
   * Default window size is set by `utils.precompute()` and is equal to 8.
   * Which means we are caching 65536 points: 256 points for every bit from 0 to 256.
   * @returns 65K precomputed points, depending on W
   */
  private precomputeWindow(W: number): JacobianPoint[] {
    const windows = CURVE.nBits / W + 1;
    const points: JacobianPoint[] = [];
    let p: JacobianPoint = this;
    let base = p;
    for (let window = 0; window < windows; window++) {
      base = p;
      points.push(base);
      for (let i = 1; i < 2 ** (W - 1); i++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }

  /**
   * Implements w-ary non-adjacent form for calculating ec multiplication.
   * @param n
   * @param affinePoint optional 2d point to save cached precompute windows on it.
   * @returns real and fake (for const-time) points
   */
  private wNAF(n: bigint, affinePoint?: Point): { p: JacobianPoint; f: JacobianPoint } {
    if (!affinePoint && this.equals(JacobianPoint.BASE)) affinePoint = Point.BASE;
    const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
    if (256 % W) {
      throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
    }

    // Calculate precomputes on a first run, reuse them after
    let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
    if (!precomputes) {
      precomputes = this.precomputeWindow(W);
      if (affinePoint && W !== 1) {
        precomputes = JacobianPoint.normalizeZ(precomputes);
        pointPrecomputes.set(affinePoint, precomputes);
      }
    }

    // Initialize real and fake points for const-time
    let p = JacobianPoint.ZERO;
    let f = JacobianPoint.ZERO;

    const windows = 1 + CURVE.nBits / W; // W=8 17
    const windowSize = 2 ** (W - 1); // W=8 128
    const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b11111111 for W=8
    const maxNumber = 2 ** W; // W=8 256
    const shiftBy = BigInt(W); // W=8 8

    for (let window = 0; window < windows; window++) {
      const offset = window * windowSize;
      // Extract W bits.
      let wbits = Number(n & mask);

      // Shift number by W bits.
      n >>= shiftBy;

      // If the bits are bigger than max size, we'll split those.
      // +224 => 256 - 32
      if (wbits > windowSize) {
        wbits -= maxNumber;
        n += 1n;
      }

      // Check if we're onto Zero point.
      // Add random point inside current window to f.
      const offset1 = offset;
      const offset2 = offset + Math.abs(wbits) - 1;
      const cond1 = window % 2 !== 0;
      const cond2 = wbits < 0;
      if (wbits === 0) {
        // The most important part for const-time getPublicKey
        f = f.add(constTimeNegate(cond1, precomputes[offset1]));
      } else {
        p = p.add(constTimeNegate(cond2, precomputes[offset2]));
      }
    }
    return { p, f };
  }

  /**
   * Constant time multiplication.
   * Uses wNAF method. Windowed method may be 10% faster,
   * but takes 2x longer to generate and consumes 2x memory.
   * @param scalar by which the point would be multiplied
   * @param affinePoint optional point ot save cached precompute windows on it
   * @returns New point
   */
  multiply(scalar: number | bigint, affinePoint?: Point): JacobianPoint {
    let n = normalizeScalar(scalar);

    // Real point.
    let point: JacobianPoint;
    // Fake point, we use it to achieve constant-time multiplication.
    let fake: JacobianPoint;
    const { p, f } = this.wNAF(n, affinePoint);
    point = p;
    fake = f;
    // Normalize `z` for both points, but return only real one
    return JacobianPoint.normalizeZ([point, fake])[0];
  }

  // Converts Jacobian point to affine (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  // (x, y, z) ∋ (x=x/z², y=y/z³)
  // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#scaling-z
  toAffine(invZ?: bigint): Point {
    const { x, y, z } = this;
    const is0 = this.equals(JacobianPoint.ZERO);
    if (invZ == null) invZ = is0 ? 8n : invert(z); // 8 was chosen arbitrarily
    const iz1 = invZ; // A
    const iz2 = mod(iz1 * iz1); // AA = A^2
    const iz3 = mod(iz2 * iz1); // AAA = A^2 * A = A^3
    const ax = mod(x * iz2); // X3 = X1*AA
    const ay = mod(y * iz3); // Y3 = Y1*AA*A
    const zz = mod(z * iz1);
    if (is0) return Point.ZERO;
    if (zz !== 1n) throw new Error('invZ was invalid');
    return new Point(ax, ay);
  }
}

// Const-time utility for wNAF
function constTimeNegate(condition: boolean, item: JacobianPoint) {
  const neg = item.negate();
  return condition ? neg : item;
}

// Stores precomputed values for points.
const pointPrecomputes = new WeakMap<Point, JacobianPoint[]>();

/**
 * Default Point works in default aka affine coordinates: (x, y)
 */
export class Point {
  /**
   * Base point aka generator. public_key = Point.BASE * private_key
   */
  static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
  /**
   * Identity point aka point at infinity. point = point + zero_point
   */
  static ZERO: Point = new Point(0n, 0n);
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  _WINDOW_SIZE?: number;

  constructor(readonly x: bigint, readonly y: bigint) {}

  // "Private method", don't use it directly
  _setWindowSize(windowSize: number) {
    this._WINDOW_SIZE = windowSize;
    pointPrecomputes.delete(this);
  }

  // Checks for y % 2 == 0
  hasEvenY() {
    return this.y % 2n === 0n;
  }

  private static fromUncompressedHex(bytes: Uint8Array) {
    const x = bytesToNumber(bytes.subarray(1, 33));
    const y = bytesToNumber(bytes.subarray(33, 65));
    const point = new Point(x, y);
    point.assertValidity();
    return point;
  }
  /**
   * Converts hash string or Uint8Array to Point.
   * @param hex 33/65-byte (ECDSA) hex
   */
  static fromHex(hex: Hex): Point {
    const bytes = ensureBytes(hex);
    const len = bytes.length;
    const header = bytes[0];
    // this.assertValidity() is done inside of those two functions
    if (len === 65 && header === 0x04) return this.fromUncompressedHex(bytes);
    throw new Error(
      `Point.fromHex: received invalid point. Expected 32-33 compressed bytes or 65 uncompressed bytes, not ${len}`
    );
  }

  // Multiplies generator point by privateKey.
  static fromPrivateKey(privateKey: PrivKey) {
    return Point.BASE.multiply(normalizePrivateKey(privateKey));
  }

  /**
   * Recovers public key from ECDSA signature.
   * https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery
   * ```
   * recover(r, s, h) where
   *   u1 = hs^-1 mod n
   *   u2 = sr^-1 mod n
   *   Q = u1⋅G + u2⋅R
   * ```
   */
  static fromSignature(msgHash: Hex, signature: Sig, recovery: number): Point {
    msgHash = ensureBytes(msgHash);
    const h = truncateHash(msgHash);
    const { r, s } = normalizeSignature(signature);
    if (recovery !== 0 && recovery !== 1) {
      throw new Error('Cannot recover signature: invalid recovery bit');
    }
    const prefix = recovery & 1 ? '03' : '02';
    const R = Point.fromHex(prefix + numTo32bStr(r));
    const { n } = CURVE;
    const rinv = invert(r, n);
    // Q = u1⋅G + u2⋅R
    const u1 = mod(-h * rinv, n);
    const u2 = mod(s * rinv, n);
    const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
    if (!Q) throw new Error('Cannot recover signature: point at infinify');
    Q.assertValidity();
    return Q;
  }

  toRawBytes(): Uint8Array {
    return hexToBytes(this.toHex());
  }

  toHex(): string {
    return `04${numTo32bStr(this.x)}${numTo32bStr(this.y)}`;
  }

  toHexX() {
    return numTo32bStr(this.x);
  }

  toRawX() {
    return hexToBytes(this.toHexX());
  }

  // A point on curve is valid if it conforms to equation.
  assertValidity(): void {
    const msg = 'Point is not on elliptic curve';
    const { x, y } = this;
    if (!isValidFieldElement(x) || !isValidFieldElement(y)) throw new Error(msg);
    const left = mod(y * y);
    const right = weierstrass(x);
    if (mod(left - right) !== 0n) throw new Error(msg);
  }

  equals(other: Point): boolean {
    return this.x === other.x && this.y === other.y;
  }

  // Returns the same point with inverted `y`
  negate() {
    return new Point(this.x, mod(-this.y));
  }

  // Adds point to itself
  double() {
    return JacobianPoint.fromAffine(this).double().toAffine();
  }

  // Adds point to other point
  add(other: Point) {
    return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
  }

  // Subtracts other point from the point
  subtract(other: Point) {
    return this.add(other.negate());
  }

  multiply(scalar: number | bigint) {
    return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
  }

  /**
   * Efficiently calculate `aP + bQ`.
   * Unsafe, can expose private key, if used incorrectly.
   * TODO: Utilize Shamir's trick
   * @returns non-zero affine point
   */
  multiplyAndAddUnsafe(Q: Point, a: bigint, b: bigint): Point | undefined {
    const P = JacobianPoint.fromAffine(this);
    const aP = a === 0n || a === 1n || this !== Point.BASE ? P.multiplyUnsafe(a) : P.multiply(a);
    const bQ = JacobianPoint.fromAffine(Q).multiplyUnsafe(b);
    const sum = aP.add(bQ);
    return sum.equals(JacobianPoint.ZERO) ? undefined : sum.toAffine();
  }
}

function sliceDER(s: string): string {
  // Proof: any([(i>=0x80) == (int(hex(i).replace('0x', '').zfill(2)[0], 16)>=8)  for i in range(0, 256)])
  // Padding done by numberToHex
  return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
}

function parseDERInt(data: Uint8Array) {
  if (data.length < 2 || data[0] !== 0x02) {
    throw new Error(`Invalid signature integer tag: ${bytesToHex(data)}`);
  }
  const len = data[1];
  const res = data.subarray(2, len + 2);
  if (!len || res.length !== len) {
    throw new Error(`Invalid signature integer: wrong length`);
  }
  // Strange condition, its not about length, but about first bytes of number.
  if (res[0] === 0x00 && res[1] <= 0x7f) {
    throw new Error('Invalid signature integer: trailing length');
  }
  return { data: bytesToNumber(res), left: data.subarray(len + 2) };
}

function parseDERSignature(data: Uint8Array) {
  if (data.length < 2 || data[0] != 0x30) {
    throw new Error(`Invalid signature tag: ${bytesToHex(data)}`);
  }
  if (data[1] !== data.length - 2) {
    throw new Error('Invalid signature: incorrect length');
  }
  const { data: r, left: sBytes } = parseDERInt(data.subarray(2));
  const { data: s, left: rBytesLeft } = parseDERInt(sBytes);
  if (rBytesLeft.length) {
    throw new Error(`Invalid signature: left bytes after parsing: ${bytesToHex(rBytesLeft)}`);
  }
  return { r, s };
}

// Represents ECDSA signature with its (r, s) properties
export class Signature {
  constructor(readonly r: bigint, readonly s: bigint) {
    this.assertValidity();
  }

  // pair (32 bytes of r, 32 bytes of s)
  static fromCompact(hex: Hex) {
    const arr = hex instanceof Uint8Array;
    const name = 'Signature.fromCompact';
    if (typeof hex !== 'string' && !arr)
      throw new TypeError(`${name}: Expected string or Uint8Array`);
    const str = arr ? bytesToHex(hex) : hex;
    if (str.length !== 128) throw new Error(`${name}: Expected 64-byte hex`);
    return new Signature(hexToNumber(str.slice(0, 64)), hexToNumber(str.slice(64, 128)));
  }

  // DER encoded ECDSA signature
  // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
  static fromDER(hex: Hex) {
    const arr = hex instanceof Uint8Array;
    if (typeof hex !== 'string' && !arr)
      throw new TypeError(`Signature.fromDER: Expected string or Uint8Array`);
    const { r, s } = parseDERSignature(arr ? hex : hexToBytes(hex));
    return new Signature(r, s);
  }

  // Don't use this method
  static fromHex(hex: Hex) {
    return this.fromDER(hex);
  }

  assertValidity(): void {
    const { r, s } = this;
    if (!isWithinCurveOrder(r)) throw new Error('Invalid Signature: r must be 0 < r < n');
    if (!isWithinCurveOrder(s)) throw new Error('Invalid Signature: s must be 0 < s < n');
  }

  // Default signatures are always low-s, to prevent malleability.
  // sign(canonical: true) always produces low-s sigs.
  // verify(strict: true) always fails for high-s.
  // We don't provide `hasHighR` https://github.com/bitcoin/bitcoin/pull/13666
  hasHighS(): boolean {
    const HALF = CURVE.n >> 1n;
    return this.s > HALF;
  }

  normalizeS(): Signature {
    return this.hasHighS() ? new Signature(this.r, CURVE.n - this.s) : this;
  }

  // DER-encoded
  toDERRawBytes(isCompressed = false) {
    return hexToBytes(this.toDERHex(isCompressed));
  }
  toDERHex(isCompressed = false) {
    const sHex = sliceDER(numberToHexUnpadded(this.s));
    if (isCompressed) return sHex;
    const rHex = sliceDER(numberToHexUnpadded(this.r));
    const rLen = numberToHexUnpadded(rHex.length / 2);
    const sLen = numberToHexUnpadded(sHex.length / 2);
    const length = numberToHexUnpadded(rHex.length / 2 + sHex.length / 2 + 4);
    return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
  }

  // Don't use these methods. Use toDER* or toCompact* for explicitness.
  toRawBytes() {
    return this.toDERRawBytes();
  }
  toHex() {
    return this.toDERHex();
  }

  // 32 bytes of r, then 32 bytes of s
  toCompactRawBytes() {
    return hexToBytes(this.toCompactHex());
  }
  toCompactHex() {
    return numTo32bStr(this.r) + numTo32bStr(this.s);
  }
}

// Concatenates several Uint8Arrays into one.
// TODO: check if we're copying data instead of moving it and if that's ok
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  if (!arrays.every((b) => b instanceof Uint8Array)) throw new Error('Uint8Array list expected');
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

// Convert between types
// ---------------------

const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a: Uint8Array): string {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += hexes[uint8a[i]];
  }
  return hex;
}

const stripLeadingZeros = (s: string) => s.replace(/^0+/gm, '');
const bytesToHexEth = (uint8a: Uint8Array): string => `0x${stripLeadingZeros(bytesToHex(uint8a))}`;
const numberToHexEth = (num: bigint | number) => `0x${num.toString(16)}`;

const POW_2_256 = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000');
function numTo32bStr(num: bigint): string {
  if (typeof num !== 'bigint') throw new Error('Expected bigint');
  if (!(0n <= num && num < POW_2_256)) throw new Error('Expected number < 2^256');
  return num.toString(16).padStart(64, '0');
}

function numTo32b(num: bigint): Uint8Array {
  const b = hexToBytes(numTo32bStr(num));
  if (b.length !== 32) throw new Error('Error: expected 32 bytes');
  return b;
}

function numberToHexUnpadded(num: number | bigint): string {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  return BigInt(`0x${strip0x(hex)}`);
}

function strip0x(hex: string) {
  return hex.replace(/^0x/i, '');
}

// Caching slows it down 2-3x
function hexToBytes(hex: string): Uint8Array {
  // Stakware has eth-like hexes
  hex = strip0x(hex);
  if (hex.length & 1) hex = '0' + hex; // padding
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

// Big Endian
function bytesToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

function ensureBytes(hex: Hex): Uint8Array {
  // Uint8Array.from() instead of hash.slice() because node.js Buffer
  // is instance of Uint8Array, and its slice() creates **mutable** copy
  return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
}

function normalizeScalar(num: number | bigint): bigint {
  if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0) return BigInt(num);
  if (typeof num === 'bigint' && isWithinCurveOrder(num)) return num;
  throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
}

// -------------------------

// Calculates a modulo b
function mod(a: bigint, b: bigint = CURVE.P): bigint {
  const result = a % b;
  return result >= 0n ? result : b + result;
}

// Inverses number over modulo
function invert(number: bigint, modulo: bigint = CURVE.P): bigint {
  if (number === 0n || modulo <= 0n) {
    throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
  }
  // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== 1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

/**
 * Takes a list of numbers, efficiently inverts all of them.
 * @param nums list of bigints
 * @param p modulo
 * @returns list of inverted bigints
 * @example
 * invertBatch([1n, 2n, 4n], 21n);
 * // => [1n, 11n, 16n]
 */
function invertBatch(nums: bigint[], p: bigint = CURVE.P): bigint[] {
  const scratch = new Array(nums.length);
  // Walk from first to last, multiply them by each other MOD p
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (num === 0n) return acc;
    scratch[i] = acc;
    return mod(acc * num, p);
  }, 1n);
  // Invert last element
  const inverted = invert(lastMultiplied, p);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (num === 0n) return acc;
    scratch[i] = mod(acc * scratch[i], p);
    return mod(acc * num, p);
  }, inverted);
  return scratch;
}

// Ensures ECDSA message hashes are 32 bytes and < curve order
function truncateHash(hash: Uint8Array, truncateOnly = false, fixTruncation = true): bigint {
  // TODO: cleanup, ugly code
  // Fix truncation
  if (fixTruncation) {
    let hashS = bytesToNumber(hash).toString(16);
    if (hashS.length === 63) {
      hashS += '0';
      hash = hexToBytes(hashS);
    }
  }
  // Truncate zero bytes on left (compat with elliptic)
  while (hash[0] === 0) hash = hash.subarray(1);

  const { n } = CURVE;
  const byteLength = hash.length;
  const delta = byteLength * 8 - CURVE.nBits; // size of curve.n (252 bits)
  let h = bytesToNumber(hash);
  if (delta > 0) h = h >> BigInt(delta);
  if (!truncateOnly && h >= n) h -= n;
  return h;
}

// RFC6979 related code
type RecoveredSig = { sig: Signature; recovery: number };
type U8A = Uint8Array;

type Sha256FnSync = (...messages: Uint8Array[]) => Uint8Array;
type HmacFnSync = (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;

const sha256Sync: Sha256FnSync = (...msgs) => {
  const h = sha256.create();
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

const hmacSha256Sync: HmacFnSync = (key, ...msgs) => {
  const h = hmac.create(sha256, key);
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

export const utils = {
  bytesToHex,
  bytesToHexEth,
  hexToBytes,
  concatBytes,
  mod,
  invert,
  isValidPrivateKey(privateKey: PrivKey) {
    try {
      normalizePrivateKey(privateKey);
      return true;
    } catch (error) {
      return false;
    }
  },
  _bigintTo32Bytes: numTo32b,
  _normalizePrivateKey: normalizePrivateKey,
  /**
   * Can take 40 or more bytes of uniform input e.g. from CSPRNG or KDF
   * and convert them into private key, with the modulo bias being neglible.
   * As per FIPS 186 B.4.1.
   * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
   * @param hash hash output from sha512, or a similar function
   * @returns valid private key
   */
  hashToPrivateKey: (hash: Hex): Uint8Array => {
    hash = ensureBytes(hash);
    if (hash.length < 40 || hash.length > 1024)
      throw new Error('Expected 40-1024 bytes of private key as per FIPS 186');
    const num = mod(bytesToNumber(hash), CURVE.n - 1n) + 1n;
    return numTo32b(num);
  },
  randomBytes,
  // Takes curve order + 64 bits from CSPRNG
  // so that modulo bias is neglible, matches FIPS 186 B.1.1.
  randomPrivateKey: (): Uint8Array => utils.hashToPrivateKey(utils.randomBytes(40)),
  sha256Sync,
  hmacSha256Sync,
  /**
   * 1. Returns cached point which you can use to pass to `getSharedSecret` or `#multiply` by it.
   * 2. Precomputes point multiplication table. Is done by default on first `getPublicKey()` call.
   * If you want your first getPublicKey to take 0.16ms instead of 20ms, make sure to call
   * utils.precompute() somewhere without arguments first.
   * @param windowSize 2, 4, 8, 16
   * @returns cached point
   */
  precompute(windowSize = 8, point = Point.BASE): Point {
    const cached = point === Point.BASE ? point : new Point(point.x, point.y);
    cached._setWindowSize(windowSize);
    cached.multiply(3n);
    return cached;
  },
};

// Minimal HMAC-DRBG (NIST 800-90) for signatures
// Used only for RFC6979, does not fully implement DRBG spec.
class HmacDrbg {
  k: Uint8Array;
  v: Uint8Array;
  counter: number;
  constructor() {
    // Step B, Step C
    this.v = new Uint8Array(32).fill(1);
    this.k = new Uint8Array(32).fill(0);
    this.counter = 0;
  }
  private hmacSync(...values: Uint8Array[]) {
    return hmacSha256Sync(this.k, ...values);
  }
  incr() {
    if (this.counter >= 1000) throw new Error('Tried 1,000 k values for sign(), all were invalid');
    this.counter += 1;
  }
  reseedSync(seed = new Uint8Array()) {
    this.k = this.hmacSync(this.v, Uint8Array.from([0x00]), seed);
    this.v = this.hmacSync(this.v);
    if (seed.length === 0) return;
    this.k = this.hmacSync(this.v, Uint8Array.from([0x01]), seed);
    this.v = this.hmacSync(this.v);
  }
  generateSync(): Uint8Array {
    this.incr();
    this.v = this.hmacSync(this.v);
    return this.v;
  }
  // There is no need in clean() method
  // It's useless, there are no guarantees with JS GC
  // whether bigints are removed even if you clean Uint8Arrays.
}

function isWithinCurveOrder(num: bigint): boolean {
  return 0n < num && num < CURVE.n;
}

function isValidFieldElement(num: bigint): boolean {
  return 0n < num && num < CURVE.P;
}

/**
 * Converts signature params into point & r/s, checks them for validity.
 * k must be in range [1, n-1]
 * @param k signature's k param: deterministic in our case, random in non-rfc6979 sigs
 * @param m message that would be signed
 * @param d private key
 * @returns Signature with its point on curve Q OR undefined if params were invalid
 */
function kmdToSig(kBytes: Uint8Array, m: bigint, d: bigint): RecoveredSig | undefined {
  const k = truncateHash(kBytes, true, false);
  if (!isWithinCurveOrder(k)) return;
  // Important: all mod() calls in the function must be done over `n`
  const { n } = CURVE;
  const q = Point.BASE.multiply(k);
  // r = x mod n
  const r = mod(q.x, n);
  if (r === 0n) return;
  // s = (1/k * (m + dr) mod n
  const s = mod(invert(k, n) * mod(m + d * r, n), n);
  if (s === 0n) return;
  const sig = new Signature(r, s);
  const recovery = (q.x === sig.r ? 0 : 2) | Number(q.y & 1n);
  return { sig, recovery };
}

function normalizePrivateKey(key: PrivKey): bigint {
  let num: bigint;
  if (typeof key === 'bigint') {
    num = key;
  } else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
    num = BigInt(key);
  } else if (typeof key === 'string') {
    key = strip0x(key).padStart(64, '0'); // Eth-like hexes
    if (key.length !== 64) throw new Error('Expected 32 bytes of private key');
    num = hexToNumber(key);
  } else if (key instanceof Uint8Array) {
    if (key.length !== 32) throw new Error('Expected 32 bytes of private key');
    num = bytesToNumber(key);
  } else {
    throw new TypeError('Expected valid private key');
  }
  if (!isWithinCurveOrder(num)) throw new Error('Expected private key: 0 < key < n');
  return num;
}

/**
 * Normalizes hex, bytes, Point to Point. Checks for curve equation.
 */
function normalizePublicKey(publicKey: PubKey): Point {
  if (publicKey instanceof Point) {
    publicKey.assertValidity();
    return publicKey;
  } else {
    return Point.fromHex(publicKey);
  }
}

/**
 * Signatures can be in 64-byte compact representation,
 * or in (variable-length)-byte DER representation.
 * Since DER could also be 64 bytes, we check for it first.
 */
function normalizeSignature(signature: Sig): Signature {
  if (signature instanceof Signature) {
    signature.assertValidity();
    return signature;
  }
  try {
    return Signature.fromDER(signature);
  } catch (error) {
    return Signature.fromCompact(signature);
  }
}

/**
 * Computes public key for secp256k1 private key.
 * @param privateKey 32-byte private key
 * @returns Public key, full (65-byte)
 */
export function getPublicKey(privateKey: PrivKey): Bytes {
  return Point.fromPrivateKey(privateKey).toRawBytes();
}

/**
 * Recovers public key from signature and recovery bit. Throws on invalid sig/hash.
 * @param msgHash message hash
 * @param signature DER or compact sig
 * @param recovery 0 or 1
 * @returns Public key (uncompressed)
 */
export function recoverPublicKey(msgHash: Hex, signature: Sig, recovery: number): Uint8Array {
  return Point.fromSignature(msgHash, signature, recovery).toRawBytes();
}

/**
 * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
 */
function isProbPub(item: PrivKey | PubKey): boolean {
  const arr = item instanceof Uint8Array;
  const str = typeof item === 'string';
  const len = (arr || str) && (item as Hex).length;
  if (arr) return len === 33 || len === 65;
  if (str) return len === 66 || len === 130;
  if (item instanceof Point) return true;
  return false;
}

/**
 * ECDH (Elliptic Curve Diffie Hellman) implementation.
 * 1. Checks for validity of private key
 * 2. Checks for the public key of being on-curve
 * @param privateA private key
 * @param publicB different public key
 * @returns shared public key
 */
export function getSharedSecret(privateA: PrivKey, publicB: PubKey): Uint8Array {
  if (isProbPub(privateA)) throw new TypeError('getSharedSecret: first arg must be private key');
  if (!isProbPub(publicB)) throw new TypeError('getSharedSecret: second arg must be public key');
  const b = normalizePublicKey(publicB);
  b.assertValidity();
  return b.multiply(normalizePrivateKey(privateA)).toRawBytes();
}

type Entropy = Hex | true;
type OptsOther = { canonical?: boolean; der?: boolean; extraEntropy?: Entropy };
type OptsRecov = { recovered: true } & OptsOther;
type OptsNoRecov = { recovered?: false } & OptsOther;
type Opts = { recovered?: boolean } & OptsOther;
type SignOutput = Uint8Array | [Uint8Array, number];

// RFC6979 methods
function bits2int(bytes: Uint8Array) {
  const slice = bytes.length > 32 ? bytes.slice(0, 32) : bytes;
  return bytesToNumber(slice);
}
function bits2octets(bytes: Uint8Array): Uint8Array {
  const z1 = bits2int(bytes);
  const z2 = mod(z1, CURVE.n);
  return int2octets(z2 < 0n ? z1 : z2);
}
function int2octets(num: bigint): Uint8Array {
  return numTo32b(num); // prohibits >32 bytes
}

// Steps A, D of RFC6979 3.2
// Creates RFC6979 seed; converts msg/privKey to numbers.
function initSigArgs(msgHash: Hex, privateKey: PrivKey, extraEntropy?: Entropy) {
  if (msgHash == null) throw new Error(`sign: expected valid message hash, not "${msgHash}"`);
  // Step A is ignored, since we already provide hash instead of msg
  const h1 = numTo32b(truncateHash(ensureBytes(msgHash)));
  const d = normalizePrivateKey(privateKey);
  // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
  const seedArgs = [int2octets(d), bits2octets(h1)];
  // RFC6979 3.6: additional k' could be provided
  if (extraEntropy != null) {
    if (extraEntropy === true) extraEntropy = utils.randomBytes(32);
    const e = ensureBytes(extraEntropy);
    if (e.length !== 32) throw new Error('sign: Expected 32 bytes of extra data');
    seedArgs.push(e);
  }
  // seed is constructed from private key and message
  // Step D
  // V, 0x00 are done in HmacDRBG constructor.
  const seed = concatBytes(...seedArgs);
  const m = bits2int(h1);
  return { seed, m, d };
}

// Takes signature with its recovery bit, normalizes it
// Produces DER/compact signature and proper recovery bit
function finalizeSig(recSig: RecoveredSig, opts: OptsNoRecov | OptsRecov): SignOutput {
  let { sig, recovery } = recSig;
  const { canonical, der, recovered } = Object.assign({ canonical: true, der: true }, opts);
  if (canonical && sig.hasHighS()) {
    sig = sig.normalizeS();
    recovery ^= 1;
  }
  const hashed = der ? sig.toDERRawBytes() : sig.toCompactRawBytes();
  return recovered ? [hashed, recovery] : hashed;
}

/**
 * Signs message hash (not message: you need to hash it by yourself).
 * @param opts `recovered, canonical, der, extraEntropy`
 */
function sign(msgHash: Hex, privKey: PrivKey, opts: OptsRecov): [U8A, number];
function sign(msgHash: Hex, privKey: PrivKey, opts?: OptsNoRecov): U8A;
function sign(msgHash: Hex, privKey: PrivKey, opts: Opts = CURVE.signOpts): SignOutput {
  // Steps A, D of RFC6979 3.2.
  const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
  let sig: RecoveredSig | undefined;
  // Steps B, C, D, E, F, G
  const drbg = new HmacDrbg();
  drbg.reseedSync(seed);
  // Step H3, repeat until k is in range [1, n-1]
  while (!(sig = kmdToSig(drbg.generateSync(), m, d))) drbg.reseedSync();
  return finalizeSig(sig, opts);
}
export { sign };

/**
 * Verifies a signature against message hash and public key.
 * Rejects non-canonical / high-s signatures by default: to override,
 * specify option `{strict: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
 *
 * ```
 * verify(r, s, h, P) where
 *   U1 = hs^-1 mod n
 *   U2 = rs^-1 mod n
 *   R = U1⋅G - U2⋅P
 *   mod(R.x, n) == r
 * ```
 */
export function verify(
  signature: Sig,
  msgHash: Hex,
  publicKey: PubKey,
  opts: { strict?: boolean } = CURVE.verifyOpts
): boolean {
  let sig;
  try {
    sig = normalizeSignature(signature);
    msgHash = ensureBytes(msgHash);
  } catch (error) {
    return false;
  }
  const { r, s } = sig;
  if (opts.strict && sig.hasHighS()) return false;
  const h = truncateHash(msgHash);
  let P;
  try {
    P = normalizePublicKey(publicKey);
  } catch (error) {
    return false;
  }
  const { n } = CURVE;
  const sinv = invert(s, n); // s^-1
  // R = u1⋅G - u2⋅P
  const u1 = mod(h * sinv, n);
  const u2 = mod(r * sinv, n);

  // Some implementations compare R.x in jacobian, without inversion.
  // The speed-up is <5%, so we don't complicate the code.
  const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2);
  if (!R) return false;
  const v = mod(R.x, n);
  return v === r;
}

// Enable precomputes. Slows down first publicKey computation by 20ms.
Point.BASE._setWindowSize(8);

// 1. seed generation
function hashKeyWithIndex(key: Bytes, index: number) {
  let indexHex = numberToHexUnpadded(index);
  if (indexHex.length & 1) indexHex = '0' + indexHex;
  return bytesToNumber(sha256(concatBytes(key, hexToBytes(indexHex))));
}

export function grindKey(seed: Hex) {
  const _seed = ensureBytes(seed);
  const sha256mask = 2n ** 256n;
  const limit = sha256mask - mod(sha256mask, CURVE.n);
  for (let i = 0; ; i++) {
    const key = hashKeyWithIndex(_seed, i);
    // key should be in [0, limit)
    if (key < limit) return mod(key, CURVE.n).toString(16);
  }
}

export function getStarkKey(privateKey: Hex) {
  return bytesToHexEth(Point.fromPrivateKey(privateKey).toRawX());
}

export function ethSigToPrivate(signature: string) {
  signature = strip0x(signature.replace(/^0x/, ''));
  if (signature.length !== 130) throw new Error('Wrong ethereum signature');
  return grindKey(signature.substring(0, 64));
}

const MASK_31 = 2n ** 31n - 1n;
const int31 = (n: bigint) => Number(n & MASK_31);
export function getAccountPath(
  layer: string,
  application: string,
  ethereumAddress: string,
  index: number
) {
  const layerNum = int31(bytesToNumber(sha256(layer)));
  const applicationNum = int31(bytesToNumber(sha256(application)));
  const eth = hexToNumber(ethereumAddress);
  return `m/2645'/${layerNum}'/${applicationNum}'/${int31(eth)}'/${int31(eth >> 31n)}'/${index}`;
}

// https://docs.starkware.co/starkex/pedersen-hash-function.html
const PEDERSEN_POINTS = [
  new Point(
    2089986280348253421170679821480865132823066470938446095505822317253594081284n,
    1713931329540660377023406109199410414810705867260802078187082345529207694986n
  ),
  new Point(
    996781205833008774514500082376783249102396023663454813447423147977397232763n,
    1668503676786377725805489344771023921079126552019160156920634619255970485781n
  ),
  new Point(
    2251563274489750535117886426533222435294046428347329203627021249169616184184n,
    1798716007562728905295480679789526322175868328062420237419143593021674992973n
  ),
  new Point(
    2138414695194151160943305727036575959195309218611738193261179310511854807447n,
    113410276730064486255102093846540133784865286929052426931474106396135072156n
  ),
  new Point(
    2379962749567351885752724891227938183011949129833673362440656643086021394946n,
    776496453633298175483985398648758586525933812536653089401905292063708816422n
  ),
];
// for (const p of PEDERSEN_POINTS) p._setWindowSize(8);
const PEDERSEN_POINTS_JACOBIAN = PEDERSEN_POINTS.map(JacobianPoint.fromAffine);

function pedersenPrecompute(p1: JacobianPoint, p2: JacobianPoint): JacobianPoint[] {
  const out = [];
  let p = p1;
  for (let i = 0; i < 248; i++) {
    out.push(p);
    p = p.double();
  }
  p = p2;
  for (let i = 0; i < 4; i++) {
    out.push(p);
    p = p.double();
  }
  return out;
}
const PEDERSEN_POINTS1 = pedersenPrecompute(
  PEDERSEN_POINTS_JACOBIAN[1],
  PEDERSEN_POINTS_JACOBIAN[2]
);
const PEDERSEN_POINTS2 = pedersenPrecompute(
  PEDERSEN_POINTS_JACOBIAN[3],
  PEDERSEN_POINTS_JACOBIAN[4]
);

type PedersenArg = Hex | bigint | number;
function pedersenArg(arg: PedersenArg): bigint {
  let value: bigint;
  if (typeof arg === 'bigint') value = arg;
  else if (typeof arg === 'number') {
    if (!Number.isSafeInteger(arg)) throw new Error(`Invalid pedersenArg: ${arg}`);
    value = BigInt(arg);
  } else value = bytesToNumber(ensureBytes(arg));
  // [0..Fp)
  if (0n > value || value >= CURVE.P)
    throw new Error(`PedersenArg should be 0<=ARG<CURVE.P: ${value}`);
  return value;
}

function pedersenSingle(point: JacobianPoint, value: PedersenArg, constants: JacobianPoint[]) {
  let x = pedersenArg(value);
  for (let j = 0; j < 252; j++) {
    const pt = constants[j];
    if (pt.x === point.x) throw new Error('Same point');
    if ((x & 1n) !== 0n) point = point.add(pt);
    x >>= 1n;
  }
  return point;
}

// shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
export function pedersen(x: PedersenArg, y: PedersenArg) {
  let point: JacobianPoint = PEDERSEN_POINTS_JACOBIAN[0];
  point = pedersenSingle(point, x, PEDERSEN_POINTS1);
  point = pedersenSingle(point, y, PEDERSEN_POINTS2);
  // point = pedersenSingleFast(point, x, 1, 2);
  // point = pedersenSingleFast(point, y, 3, 4);
  return bytesToHexEth(point.toAffine().toRawX());
}

export function hashChain(data: PedersenArg[], fn = pedersen) {
  if (!Array.isArray(data) || data.length < 1)
    throw new Error('data should be array of at least 1 element');
  if (data.length === 1) return numberToHexEth(pedersenArg(data[0]));
  return Array.from(data)
    .reverse()
    .reduce((acc, i) => fn(i, acc));
}
// Same as hashChain, but computes hash even for single element and order is not revesed
export const computeHashOnElements = (data: PedersenArg[], fn = pedersen) =>
  [0, ...data, data.length].reduce((x, y) => fn(x, y));

const MASK_250 = 2n ** 250n - 1n;
export const keccak = (data: Bytes) => bytesToNumber(keccak_256(data)) & MASK_250;
