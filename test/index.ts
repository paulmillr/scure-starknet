import { should } from 'micro-should';
import './basic.test.ts';
import './poseidon.test.ts';
import './property.test.ts';
import './stark.test.ts';
should.runWhen(import.meta.url);
