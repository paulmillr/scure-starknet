# micro-starknet

**The package has been deprecated and is not supported. Switch to [@noble/curves](https://github.com/paulmillr/noble-curves) instead.**

```js
import * as stark from 'micro-curve-definitions/lib/stark.js';
// micro-curve-definitions is a part of @noble/curves

stark.getPublicKey(privKey)
stark.sign(msg, privKey)
stark.verify(sig, msg, pubKey)
stark.pedersen(x, y)
stark.hashChain(data, fn)
```

---

>Minimal implementation of [Starknet cryptography](https://docs.starkware.co/starkex/stark-curve.html) including Pedersen and Stark Curve.
