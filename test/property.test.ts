import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import * as starknet from '../index.js';

const FC_BIGINT = fc.bigInt(1n + 1n, starknet.Point.CURVE().n - 1n);
const FC_MAX = fc.bigInt(0n, starknet.MAX_VALUE - 1n);

describe('starknet property', () => {
  should('Point#toHex() roundtrip', () => {
    fc.assert(
      fc.property(FC_BIGINT, (x) => {
        const point1 = starknet.Point.BASE.multiply(x);
        const hex = point1.toHex(true);
        deepStrictEqual(starknet.Point.fromHex(hex).toHex(true), hex);
      })
    );
  });

  should('Signature.fromCompactHex() roundtrip', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
        const sig = new starknet.Signature(r, s);
        deepStrictEqual(starknet.Signature.fromHex(sig.toHex('compact'), 'compact'), sig);
      })
    );
  });

  should('Signature.fromDERHex() roundtrip', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
        const sig = new starknet.Signature(r, s);
        deepStrictEqual(starknet.Signature.fromHex(sig.toHex('der'), 'der'), sig);
      })
    );
  });

  should('verify()/should verify random signatures', () =>
    fc.assert(
      fc.property(FC_BIGINT, FC_MAX, (privNum, msg) => {
        const privKey = privNum.toString(16).padStart(64, '0');
        const msgHash = msg.toString(16);
        const pub = starknet.getPublicKey(privKey);
        const sig = starknet.sign(msgHash, privKey);
        deepStrictEqual(starknet.verify(sig, msgHash, pub), true);
      })
    )
  );
});

should.runWhen(import.meta.url);
