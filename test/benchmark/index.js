import bench from '@paulmillr/jsbt/bench.js';
// import * as starkwareCrypto from '@starkware-industries/starkware-crypto-utils';
import * as stark from '../../index.js';

(async () => {
  // console.log(`\x1b[36mstark\x1b[0m`);
  await bench('init', () => stark.utils.precompute(8), 1);
  const d = (() => {
    const priv = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
    const msg = 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47';
    const pub = stark.getPublicKey(priv);
    const sig = stark.sign(msg, priv);

    const privateKey = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
    const msgHash = 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47';
    // const keyPair = starkwareCrypto.default.ec.keyFromPrivate(privateKey, 'hex');
    // const publicKeyStark = starkwareCrypto.default.ec.keyFromPublic(
    //   keyPair.getPublic(true, 'hex'),
    //   'hex'
    // );
    return { priv, sig, msg, pub, msgHash };
  })();
  await bench('pedersen', () => stark.pedersen(
        '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
        '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a'
      ));
  await bench('poseidon', () => stark.poseidonHash(
    0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cbn,
    0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31an
  ));
  await bench('verify', () => {
      return stark.verify(stark.sign(d.msg, d.priv), d.msg, d.pub);
    });
})();
