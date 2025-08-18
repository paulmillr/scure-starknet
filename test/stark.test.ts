import { utf8ToBytes } from '@noble/hashes/utils.js';
import * as bip32 from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import * as starknet from '../index.js';
import { default as precomputedKeys } from './vectors/keys_precomputed.json' with { type: 'json' };
import { default as sigVec } from './vectors/rfc6979_signature_test_vector.json' with { type: 'json' };

describe('starknet', () => {
  should('custom keccak', () => {
    const value = starknet.keccak(utf8ToBytes('hello'));
    deepStrictEqual(value, 0x8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8n);
    deepStrictEqual(value < 2n ** 250n, true);
  });

  should('RFC6979', () => {
    for (const msg of sigVec.messages) {
      const { r, s } = starknet.sign(msg.hash, sigVec.private_key);
      // const { r, s } = starknet.Signature.fromDER(sig);
      deepStrictEqual(r.toString(10), msg.r);
      deepStrictEqual(s.toString(10), msg.s);
    }
  });

  should('Signatures', () => {
    const vectors = [
      {
        // Message hash of length 61.
        msg: 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47',
        r: '5f496f6f210b5810b2711c74c15c05244dad43d18ecbbdbe6ed55584bc3b0a2',
        s: '4e8657b153787f741a67c0666bad6426c3741b478c8eaa3155196fc571416f3',
      },
      {
        // Message hash of length 61, with leading zeros.
        msg: '00c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47',
        r: '5f496f6f210b5810b2711c74c15c05244dad43d18ecbbdbe6ed55584bc3b0a2',
        s: '4e8657b153787f741a67c0666bad6426c3741b478c8eaa3155196fc571416f3',
      },
      {
        // Message hash of length 62.
        msg: 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47a',
        r: '233b88c4578f0807b4a7480c8076eca5cfefa29980dd8e2af3c46a253490e9c',
        s: '28b055e825bc507349edfb944740a35c6f22d377443c34742c04e0d82278cf1',
      },
      {
        // Message hash of length 63.
        msg: '7465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47a1',
        r: 'b6bee8010f96a723f6de06b5fa06e820418712439c93850dd4e9bde43ddf',
        s: '1a3d2bc954ed77e22986f507d68d18115fa543d1901f5b4620db98e2f6efd80',
      },
    ];
    const privateKey = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
    const publicKey = starknet.getPublicKey(privateKey);
    for (const v of vectors) {
      const sig = starknet.sign(v.msg, privateKey);
      const { r, s } = sig;
      // const { r, s } = starknet.Signature.fromDER(sig);
      deepStrictEqual(r.toString(16), v.r, 'r equality');
      deepStrictEqual(s.toString(16), v.s, 's equality');
      deepStrictEqual(starknet.verify(sig, v.msg, publicKey), true, 'verify');
    }
  });

  describe('invalid signatures', () => {
    should('verify signature length', () => {
      const ecOrder = starknet.Point.CURVE().n;
      const maxEcdsaVal = 2n ** 251n;
      const maxMsgHash = maxEcdsaVal - 1n;
      const maxR = maxEcdsaVal - 1n;
      const maxS = ecOrder - 1n - 1n;
      // NOTE: original test in starknet is broken, because
      // > const maxStarkKey = maxEcdsaVal.sub(oneBn);
      // is not valid key!
      // Also, there is no checks for key bigger than maxEcdsaVal in code
      const maxStarkKey = maxEcdsaVal - 1n;
      // real key
      const maxStarkKey2 = starknet.getPublicKey(
        '7D0F499B250763F4CACF0D8D9E267D012C03503CE5DE876B33D3A3837DC90AF'
      );
      const verif = (sig, msg, key) =>
        starknet.verify(
          new starknet.Signature(sig.r, sig.s),
          msg.toString(16),
          typeof key === 'bigint' ? key.toString(16) : key
        );
      const vectors = [
        { r: 0n, s: maxS, msg: maxMsgHash, name: 'invalid r' },
        { r: maxR + 1n, s: maxS, msg: maxMsgHash, name: 'invalid r' },
        { r: maxR, s: maxS + 1n, name: 'invalid w' },
        { r: maxR, s: 0n, msg: maxMsgHash, name: 'invalid s' },
        { r: maxR, s: maxS + 1n + 1n, msg: maxMsgHash, name: 'invalid s' },
        { r: maxR, s: maxS, msg: maxMsgHash + 1n, name: 'invalid msgHash' },
      ];
      // Verify that max values actually works
      verif({ r: maxR, s: maxS }, maxMsgHash, maxStarkKey);
      verif({ r: maxR, s: maxS }, maxMsgHash, maxStarkKey2);
      for (const v of vectors) {
        throws(() => verif(v, v.msg, maxStarkKey), v.name);
        throws(() => verif(v, v.msg, maxStarkKey2), `${v.name} (second key)`);
      }
    });

    should('not verify invalid signatures', () => {
      const privKey = starknet.utils.randomPrivateKey();
      const pub = starknet.getPublicKey(privKey);
      const pubInvalid = starknet.getPublicKey(starknet.utils.randomPrivateKey());
      const msg = BigInt('0xCEFE1753E86FDC91FEA207A720F529A13D4A65886C603449AE95A846DC1E7'); // 61 char hex
      const msgHex = msg.toString(16);
      const msgHexInvalid = (msg + 1n).toString(16);
      const sig = starknet.sign(msgHex, privKey);
      const sigInvalidR = new starknet.Signature(sig.r + 1n, sig.r);
      const sigInvalidS = new starknet.Signature(sig.r, sig.r + 1n);
      const verif = starknet.verify;
      deepStrictEqual(verif(sig, msgHex, pubInvalid), false, 'verifies with invalid public key');
      deepStrictEqual(verif(sig, msgHexInvalid, pub), false, 'verifies with invalid message');
      deepStrictEqual(verif(sigInvalidR, msgHex, pub), false, 'verifies with invalid signature R');
      deepStrictEqual(verif(sigInvalidS, msgHex, pub), false, 'verifies with invalid signature S');
    });

    should('signature cross-test (with different lengths)', () => {
      const vectors = [
        {
          msg: '00',
          s: '12bcacdadecfca0773945071b371adda1bc47fce319f80aa590b06d45a996f5',
          r: '443b6a567dfeae1c8c77dc589cdde204649f85ba45e54bead543299e5888233',
        },
        {
          msg: '40DC8ABE9797B6EF5C0886AD4A78405CD393493D2B6A8733B77250F61',
          s: '49ec9e6aa783e7518ffc05ec054db3ddf2d8ad301e4ee790392841fa759431e',
          r: '78a73ac7f793e706e50871da2efc2f83c30852a90110cab71108ff6a3af864e',
        },
        {
          msg: '40DC8ABE9797B6EF5C0886AD4A78405CD393493D2B6A8733B77250F610C',
          s: '2c512662f37585497683e2d98c655e098ad4504d41d3a3b17ad0f0f9db45ddb',
          r: '5864e5d2843d4469e70282042c7675e4fcb4b530d45dd6f02ae03c8d2f5431a',
        },
        {
          msg: '40DC8ABE9797B6EF5C0886AD4A78405CD393493D2B6A8733B77250F610C1D',
          s: '7a2902b67913c013557f0ea61902a1edc8539aa1321549bef9a47dbb9af0eba',
          r: '7f313dc69e5f785a7071a9acc12a1294bce54d199a90b1ecdd39fd654c55190',
        },
        {
          msg: '40DC8ABE9797B6EF5C0886AD4A78405CD393493D2B6A8733B77250F610C1D00',
          s: '4cb6384d5b82bf873c87e02e11d32cefb1f10cc6d3d67895662d6c87c6df505',
          r: '73bab8d7be901dc6bdba59f458c3ddeb4e0264657c60ff1b42a403d69e84718',
        },
      ];
      const privKey = '7D0F499B250763F4CACF0D8D9E267D012C03503CE5DE876B33D3A3837DC90AF';
      // Code for check generate vectors:
      // const keyPair = starkwareCrypto.ec.keyFromPrivate(privKey, 'hex');
      // const keyPairPub = starkwareCrypto.ec.keyFromPublic(keyPair.getPublic(), 'BN');

      // function testSign(hh) {
      //   const s = starkwareCrypto.sign(keyPair, new BN(hh, 16));
      //   return { s: s.s.toString(16), r: s.r.toString(16) };
      // }
      // for (const v of vectors) {
      //   const res = testSign(v.msg);
      //   console.log('TTT', res);
      //   deepStrictEqual(res.s, v.s);
      //   deepStrictEqual(res.r, v.r);
      // }

      for (const v of vectors) {
        const sig = starknet.sign(v.msg, privKey);
        deepStrictEqual(sig.s.toString(16), v.s);
        deepStrictEqual(sig.r.toString(16), v.r);
      }
      // Crashes: Message not signable, invalid msgHash length.
      // {
      //   msg: '40DC8ABE9797B6EF5C0886AD4A78405CD393493D2B6A8733B77250F610C1D000',
      //   s: '4cb6384d5b82bf873c87e02e11d32cefb1f10cc6d3d67895662d6c87c6df505',
      //   r: '73bab8d7be901dc6bdba59f458c3ddeb4e0264657c60ff1b42a403d69e84718'
      // }
      throws(() =>
        starknet.sign('40DC8ABE9797B6EF5C0886AD4A78405CD393493D2B6A8733B77250F610C1D000', privKey)
      );
    });
  });

  should('Pedersen', () => {
    deepStrictEqual(
      starknet.pedersen(
        '0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
        '0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a'
      ),
      '0x30e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662'
    );
    deepStrictEqual(
      starknet.pedersen(
        '0x58f580910a6ca59b28927c08fe6c43e2e303ca384badc365795fc645d479d45',
        '0x78734f65a067be9bdb39de18434d71e79f7b6466a4b66bbd979ab9e7515fe0b'
      ),
      '0x68cc0b76cddd1dd4ed2301ada9b7c872b23875d5ff837b3a87993e0d9996b87'
    );
  });

  should('Key grinding', () => {
    deepStrictEqual(
      starknet.grindKey('86F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0519'),
      '5c8c8683596c732541a59e03007b2d30dbbbb873556fe65b5fb63c16688f941'
    );
    // Loops more than once (verified manually)
    deepStrictEqual(
      starknet.grindKey('94F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0595'),
      '33880b9aba464c1c01c9f8f5b4fc1134698f9b0a8d18505cab6cdd34d93dc02'
    );
  });

  should('Private to stark key', () => {
    deepStrictEqual(
      starknet.getStarkKey('0x178047D3869489C055D7EA54C014FFB834A069C9595186ABE04EA4D1223A03F'),
      '0x1895a6a77ae14e7987b9cb51329a5adfb17bd8e7c638f92d6892d76e51cebcf'
    );
    for (const [privKey, expectedPubKey] of Object.entries(precomputedKeys)) {
      deepStrictEqual(starknet.getStarkKey(privKey), expectedPubKey);
    }
  });

  should('Private stark key from eth signature', () => {
    const ethSignature =
      '0x21fbf0696d5e0aa2ef41a2b4ffb623bcaf070461d61cf7251c74161f82fec3a43' +
      '70854bc0a34b3ab487c1bc021cd318c734c51ae29374f2beb0e6f2dd49b4bf41c';
    deepStrictEqual(
      starknet.ethSigToPrivate(ethSignature),
      '766f11e90cd7c7b43085b56da35c781f8c067ac0d578eabdceebc4886435bda'
    );
  });

  should('Private stark key normalization', () => {
    const ethSignature =
      '0x21fbf0696d5e0aa2ef41a2b4ffb623bcaf070461d61cf7251c74161f82fec3a43' +
      '70854bc0a34b3ab487c1bc021cd318c734c51ae29374f2beb0e6f2dd49b4bf41c';
    const privateKey = starknet.ethSigToPrivate(ethSignature);
    const normalizedPrivateKey = starknet.normalizePrivateKey(privateKey);
    deepStrictEqual(privateKey, '766f11e90cd7c7b43085b56da35c781f8c067ac0d578eabdceebc4886435bda');
    deepStrictEqual(
      normalizedPrivateKey,
      '0766f11e90cd7c7b43085b56da35c781f8c067ac0d578eabdceebc4886435bda'
    );
  });

  should('Key derivation', () => {
    const layer = 'starkex';
    const application = 'starkdeployement';
    const mnemonic =
      'range mountain blast problem vibrant void vivid doctor cluster enough melody ' +
      'salt layer language laptop boat major space monkey unit glimpse pause change vibrant';
    const ethAddress = '0xa4864d977b944315389d1765ffa7e66F74ee8cd7';
    const VECTORS = [
      {
        index: 0,
        path: "m/2645'/579218131'/891216374'/1961790679'/2135936222'/0",
        privateKey: '6cf0a8bf113352eb863157a45c5e5567abb34f8d32cddafd2c22aa803f4892c',
      },
      {
        index: 7,
        path: "m/2645'/579218131'/891216374'/1961790679'/2135936222'/7",
        privateKey: '341751bdc42841da35ab74d13a1372c1f0250617e8a2ef96034d9f46e6847af',
      },
      {
        index: 598,
        path: "m/2645'/579218131'/891216374'/1961790679'/2135936222'/598",
        privateKey: '41a4d591a868353d28b7947eb132aa4d00c4a022743689ffd20a3628d6ca28c',
      },
    ];
    const hd = bip32.HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
    for (const { index, path, privateKey } of VECTORS) {
      const realPath = starknet.getAccountPath(layer, application, ethAddress, index);
      deepStrictEqual(realPath, path);
      deepStrictEqual(starknet.grindKey(hd.derive(realPath).privateKey), privateKey);
    }
  });

  // Verified against starknet.js
  should('Starknet.js cross-tests', () => {
    const privateKey = '0x019800ea6a9a73f94aee6a3d2edf018fc770443e90c7ba121e8303ec6b349279';
    // NOTE: there is no compressed keys here, getPubKey returns stark-key (which is schnorr-like X coordinate)
    // But it is not used in signing/verifying
    deepStrictEqual(
      starknet.getStarkKey(privateKey),
      '0x33f45f07e1bd1a51b45fc24ec8c8c9908db9e42191be9e169bfcac0c0d99745'
    );
    const msgHash = '0x6d1706bd3d1ba7c517be2a2a335996f63d4738e2f182144d078a1dd9997062e';
    const sig = starknet.sign(msgHash, privateKey);
    const { r, s } = sig;

    deepStrictEqual(
      r.toString(),
      '1427981024487605678086498726488552139932400435436186597196374630267616399345'
    );
    deepStrictEqual(
      s.toString(),
      '1853664302719670721837677288395394946745467311923401353018029119631574115563'
    );
    const hashMsg2 = starknet.pedersen(
      '0x33f45f07e1bd1a51b45fc24ec8c8c9908db9e42191be9e169bfcac0c0d99745',
      '1'
    );
    deepStrictEqual(hashMsg2, '0x2b0d4d43acce8ff68416f667f92ec7eab2b96f1d2224abd4d9d4d1e7fa4bb00');
    const pubKey =
      '04033f45f07e1bd1a51b45fc24ec8c8c9908db9e42191be9e169bfcac0c0d997450319d0f53f6ca077c4fa5207819144a2a4165daef6ee47a7c1d06c0dcaa3e456';
    const sig2 = new starknet.Signature(
      558858382392827003930138586379728730695763862039474863361948210004201119180n,
      2440689354481625417078677634625227600823892606910345662891037256374285369343n
    );
    deepStrictEqual(starknet.verify(sig2.toHex('der'), hashMsg2, pubKey), true);
  });
});

should.runWhen(import.meta.url);
