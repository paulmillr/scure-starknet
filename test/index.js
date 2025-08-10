import { should } from 'micro-should';
import './basic.test.js';
import './poseidon.test.js';
import './property.test.js';
import './stark.test.js';

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
