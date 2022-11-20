import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import * as starknet from '../index.js';
import { default as issue2 } from './fixtures/issue2.json' assert { type: 'json' };

should('Basic elliptic sanity check', () => {
  const g1 = starknet.Point.BASE;
  deepStrictEqual(
    g1.x.toString(16),
    '1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca'
  );
  deepStrictEqual(
    g1.y.toString(16),
    '5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f'
  );
  const g2 = g1.double();
  deepStrictEqual(
    g2.x.toString(16),
    '759ca09377679ecd535a81e83039658bf40959283187c654c5416f439403cf5'
  );
  deepStrictEqual(
    g2.y.toString(16),
    '6f524a3400e7708d5c01a28598ad272e7455aa88778b19f93b562d7a9646c41'
  );
  const g3 = g2.add(g1);
  deepStrictEqual(
    g3.x.toString(16),
    '411494b501a98abd8262b0da1351e17899a0c4ef23dd2f96fec5ba847310b20'
  );
  deepStrictEqual(
    g3.y.toString(16),
    '7e1b3ebac08924d2c26f409549191fcf94f3bf6f301ed3553e22dfb802f0686'
  );
  const g32 = g1.multiply(3);
  deepStrictEqual(
    g32.x.toString(16),
    '411494b501a98abd8262b0da1351e17899a0c4ef23dd2f96fec5ba847310b20'
  );
  deepStrictEqual(
    g32.y.toString(16),
    '7e1b3ebac08924d2c26f409549191fcf94f3bf6f301ed3553e22dfb802f0686'
  );
  const minus1 = g1.multiply(starknet.CURVE.n - 1n);
  deepStrictEqual(
    minus1.x.toString(16),
    '1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca'
  );
  deepStrictEqual(
    minus1.y.toString(16),
    '7a997f9f55b68e04841b7fe20b9139d21ac132ee541bc5cd78cfff3c91723e2'
  );
});

should('Pedersen', () => {
  deepStrictEqual(
    starknet.pedersen(2, 3),
    '5774fa77b3d843ae9167abd61cf80365a9b2b02218fc2f628494b5bdc9b33b8'
  );
  deepStrictEqual(
    starknet.pedersen(1, 2),
    '5bb9440e27889a364bcb678b1f679ecd1347acdedcbf36e83494f857cc58026'
  );
  deepStrictEqual(
    starknet.pedersen(3, 4),
    '262697b88544f733e5c6907c3e1763131e9f14c51ee7951258abbfb29415fbf'
  );
});

should('Hash chain', () => {
  deepStrictEqual(
    starknet.hashChain([1, 2, 3]),
    '5d9d62d4040b977c3f8d2389d494e4e89a96a8b45c44b1368f1cc6ec5418915'
  );
});

should('Pedersen hash edgecases', () => {
  // >>> pedersen_hash(0,0)
  // 2089986280348253421170679821480865132823066470938446095505822317253594081284
  const zero =
    2089986280348253421170679821480865132823066470938446095505822317253594081284n.toString(16);
  deepStrictEqual(starknet.pedersen(0, 0), zero);
  deepStrictEqual(starknet.pedersen(0n, 0n), zero);
  deepStrictEqual(starknet.pedersen('0', '0'), zero);
  deepStrictEqual(starknet.pedersen('0x0', '0x0'), zero);
  // >>> pedersen_hash(3618502788666131213697322783095070105623107215331596699973092056135872020475,3618502788666131213697322783095070105623107215331596699973092056135872020475)
  // 3226051580231087455100099637526672350308978851161639703631919449959447036451
  const big = 3618502788666131213697322783095070105623107215331596699973092056135872020475n;
  const bigExp =
    3226051580231087455100099637526672350308978851161639703631919449959447036451n.toString(16);
  deepStrictEqual(starknet.pedersen(big, big), bigExp);
  // >= FIELD
  const big2 = 36185027886661312136973227830950701056231072153315966999730920561358720204751n;
  throws(() => starknet.pedersen(big2, big2), 'big2');

  // FIELD -1
  const big3 = 3618502788666131213697322783095070105623107215331596699973092056135872020480n;
  const big3exp =
    3232555749487190471763097992898089327242482272407513295348046886353176778606n.toString(16);
  deepStrictEqual(starknet.pedersen(big3, big3), big3exp, 'big3');
  // FIELD
  const big4 = 3618502788666131213697322783095070105623107215331596699973092056135872020481n;
  throws(() => starknet.pedersen(big4, big4), 'big4');
  throws(() => starknet.pedersen(-1, -1), 'neg');
});

should('Pedersen hash, issue #2', () => {
  const hexData = issue2;
  // Verified with starnet.js
  const exp = '22064462ea33a6ce5272a295e0f551c5da3834f80d8444e7a4df68190b1bc42';
  const value = [...hexData, hexData.length].reduce((x, y) => starknet.pedersen(x, y), 0);
  deepStrictEqual(value, exp);
});

import * as bip32 from '@scure/bip32';
import * as bip39 from '@scure/bip39';

should('Seed derivation (example)', () => {
  const layer = 'starkex';
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

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
