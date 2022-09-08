import { describe, it } from 'mocha';
import { expect } from 'chai';
import crypto from 'node:crypto';
import  { decodeBin } from '@base32h/base32h';
import  { explodeId } from '@theroyalwhee0/snowman';
import  { identGenerator } from '../src/index';
import  {
  HMAC_ALGO,
  ALL_SIZE, ID_SIZE, RND_SIZE, VERIFY_SIZE, SIGN_SIZE,
} from '../src/constants';

/**
 * Test constants.
 */
// Set One
const verifyKey1 = 'banana1';
const signKey1 = 'apple1';
// Set Two
const verifyKey2 = '';
const signKey2 = '';
// Set Three
const verifyKey3 = 'YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY';
const signKey3   = 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ';

/**
 * Left Pad Buffer.
 */
function leftPadBuffer(buffer:Buffer, size:number, value=0):Buffer {
  if(buffer.length >= size) {
    return buffer;
  }
  return Buffer.concat([
    Buffer.alloc(size-buffer.length, value),
    buffer,
  ]);
}

/**
 * Left trim buffer.
 */
function leftTrimBuffer(buffer:Buffer, value=0):Buffer {
  let idx;
  for(idx=0; idx < buffer.length; idx++) {
    if(buffer[idx] !== value) {
      break;
    }
  }
  return idx === 0 ? buffer : buffer.slice(idx);
}

/**
 * Tests.
 */
describe('@theroyalwhee0/ident', () => {
  describe('identGenerator', () => {
    it('should be a function', () => {
      expect(identGenerator).to.be.a('function');
      expect(identGenerator.length).to.equal(1);
    });
    it('should create an iterator', () => {
      const it = identGenerator({
        signKey: signKey1, verifyKey: verifyKey1,
      });
      expect(it[Symbol.iterator]).to.be.an('function');
      const results = it.next();
      expect(results).to.be.an('object');
    });
    it('should have expected constants', () => {
      expect(ID_SIZE).to.equal(8);
      expect(RND_SIZE).to.equal(8);
      expect(VERIFY_SIZE).to.equal(2);
      expect(SIGN_SIZE).to.equal(4);
      expect(ALL_SIZE).to.equal(ID_SIZE+RND_SIZE+VERIFY_SIZE+SIGN_SIZE);
      expect(HMAC_ALGO).to.equal('sha256');
    });
    it('with a verify-key and sign-key', async () => {
      const it = identGenerator({
        signKey: signKey1, verifyKey: verifyKey1,
      });
      const { value, done } = it.next();
      expect(value).to.be.a('string');
      expect(done).to.equal(false);
      expect(value).to.match(/^[123456789ABCDEFGHJKLMNPQRTVWXYZ][0123456789ABCDEFGHJKLMNPQRTVWXYZ]+$/);
      // Decode values.
      const decoded = Buffer.from(decodeBin(value as string));
      const trimmed = leftTrimBuffer(decoded, 0);
      expect(trimmed.length).to.be.lte(ALL_SIZE);
      const buffer = leftPadBuffer(trimmed, ALL_SIZE);
      let start = 0, end = ID_SIZE;
      const idBuffer = buffer.slice(start, end);
      const id = idBuffer.readBigUInt64BE();
      start = end; end += RND_SIZE;
      start = end; end += VERIFY_SIZE;
      const verify  = buffer.slice(start, end);
      start = end; end += SIGN_SIZE;
      const sign  = buffer.slice(start, end);
      // Check ID.
      const [ timestamp, node, sequence, isValid ] = explodeId(id);
      expect(isValid).to.be.true;
      expect(timestamp).to.be.a('number');
      expect(node).to.equal(0);
      expect(sequence).to.be.a('number');
      // Check verify hmac.
      const hmacVerify = crypto.createHmac(HMAC_ALGO, verifyKey1);
      const verifyBuffer = buffer.slice(0, ID_SIZE+RND_SIZE);
      const verifyCheck = hmacVerify.update(verifyBuffer).digest();
      expect([...verifyCheck.slice(0, VERIFY_SIZE)]).to.eql([...verify]);
      // Check sign hmac.
      const hmacSign = crypto.createHmac(HMAC_ALGO, signKey1);
      const signBuffer = buffer.slice(0, ID_SIZE+RND_SIZE+VERIFY_SIZE);
      const signCheck = hmacSign.update(signBuffer).digest();
      expect([...signCheck.slice(0, SIGN_SIZE)]).to.eql([...sign]);
    });
    it('should generate a sequence of valid idents over time', async () => {
      const generated = new Set();
      const it = identGenerator({
        signKey: signKey1, verifyKey: verifyKey1,
      });
      for(let idx=0; idx < 2000; idx++) {
        const { value, done } = it.next() as {value:string, done:boolean };
        expect(done).to.equal(false);
        expect(value).to.be.a('string');
        expect(value).to.match(/^[123456789ABCDEFGHJKLMNPQRTVWXYZ][0123456789ABCDEFGHJKLMNPQRTVWXYZ]+$/);
        // Should not repeat values.
        expect(generated.has(value)).to.be.false;
        generated.add(value);
        // Decode values.
        const decoded = Buffer.from(decodeBin(value));
        const trimmed = leftTrimBuffer(decoded, 0);
        expect(trimmed.length).to.be.lte(ALL_SIZE);
        const buffer = leftPadBuffer(trimmed, ALL_SIZE);
        let start = 0, end = ID_SIZE;
        const idBuffer = buffer.slice(start, end);
        const id = idBuffer.readBigUInt64BE();
        start = end; end += RND_SIZE;
        start = end; end += VERIFY_SIZE;
        const verify  = buffer.slice(start, end);
        start = end; end += SIGN_SIZE;
        const sign  = buffer.slice(start, end);
        // Check ID.
        const [ timestamp, node, sequence, isValid ] = explodeId(id);
        expect(isValid).to.be.true;
        expect(timestamp).to.be.a('number');
        expect(node).to.equal(0);
        expect(sequence).to.be.a('number');
        // Check verify hmac.
        const hmacVerify = crypto.createHmac(HMAC_ALGO, verifyKey1);
        const verifyBuffer = buffer.slice(0, ID_SIZE+RND_SIZE);
        const verifyCheck = hmacVerify.update(verifyBuffer).digest();
        expect([...verifyCheck.slice(0, VERIFY_SIZE)]).to.eql([...verify]);
        // Check sign hmac.
        const hmacSign = crypto.createHmac(HMAC_ALGO, signKey1);
        const signBuffer = buffer.slice(0, ID_SIZE+RND_SIZE+VERIFY_SIZE);
        const signCheck = hmacSign.update(signBuffer).digest();
        expect([...signCheck.slice(0, SIGN_SIZE)]).to.eql([...sign]);
        if(idx % 400 === 0) {
          // Rest every once and a while.
          await new Promise(setImmediate);
        }
      }
    });
    it('should create ident with small fixed test values', async () => {
      const it = identGenerator({
        node: 0,
        verifyKey: verifyKey2,
        signKey: signKey2,
        getRandomBytes(size) {
          return Buffer.alloc(size, 0x00);
        },
        idOptions: {
          offset: 0,
          getTimestamp() {
            return 1;
          },
        },
      });
      const { value, done } = it.next() as {value:string, done:boolean };
      expect(value).to.be.a('string');
      expect(done).to.equal(false);
      expect(value).to.match(/^[123456789ABCDEFGHJKLMNPQRTVWXYZ][0123456789ABCDEFGHJKLMNPQRTVWXYZ]+$/);
      // Decode values.
      const decoded = Buffer.from(decodeBin(value));
      const trimmed = leftTrimBuffer(decoded, 0);
      expect(trimmed.length).to.be.lte(ALL_SIZE);
      const buffer = leftPadBuffer(trimmed, ALL_SIZE);
      let start = 0, end = ID_SIZE;
      const idBuffer = buffer.slice(start, end);
      const id = idBuffer.readBigUInt64BE();
      start = end; end += RND_SIZE;
      start = end; end += VERIFY_SIZE;
      const verify  = buffer.slice(start, end);
      start = end; end += SIGN_SIZE;
      const sign  = buffer.slice(start, end);
      // Check ID.
      const [ timestamp, node, sequence, isValid ] = explodeId(id);
      expect(isValid).to.be.true;
      expect(timestamp).to.be.a('number');
      expect(node).to.equal(0);
      expect(sequence).to.equal(0);
      // Check verify hmac.
      const hmacVerify = crypto.createHmac(HMAC_ALGO, verifyKey2);
      const verifyBuffer = buffer.slice(0, ID_SIZE+RND_SIZE);
      const verifyCheck = hmacVerify.update(verifyBuffer).digest();
      expect([...verifyCheck.slice(0, VERIFY_SIZE)]).to.eql([...verify]);
      // Check sign hmac.
      const hmacSign = crypto.createHmac(HMAC_ALGO, signKey2);
      const signBuffer = buffer.slice(0, ID_SIZE+RND_SIZE+VERIFY_SIZE);
      const signCheck = hmacSign.update(signBuffer).digest();
      expect([...signCheck.slice(0, SIGN_SIZE)]).to.eql([...sign]);
      expect(value).to.equal('1000000000000000005Z4F3HZMWV');
      expect(value.length).to.equal(28);
    });
    it('should create ident with large fixed test values', async () => {
      const it = identGenerator({
        node: 1023,
        verifyKey: verifyKey3,
        signKey: signKey3,
        getRandomBytes(size) {
          return Buffer.alloc(size, 0xFF);
        },
        idOptions: {
          offset: 0,
          getTimestamp() {
            return 2**40-1;
          },
        },
      });
      const { value, done } = it.next() as {value:string, done:boolean };
      expect(value).to.be.a('string');
      expect(done).to.equal(false);
      expect(value).to.match(/^[123456789ABCDEFGHJKLMNPQRTVWXYZ][0123456789ABCDEFGHJKLMNPQRTVWXYZ]+$/);
      // Decode values.
      const decoded = Buffer.from(decodeBin(value));
      const trimmed = leftTrimBuffer(decoded, 0);
      expect(trimmed.length).to.be.lte(ALL_SIZE);
      const buffer = leftPadBuffer(trimmed, ALL_SIZE);
      let start = 0, end = ID_SIZE;
      const idBuffer = buffer.slice(start, end);
      const id = idBuffer.readBigUInt64BE();
      start = end; end += RND_SIZE;
      start = end; end += VERIFY_SIZE;
      const verify  = buffer.slice(start, end);
      start = end; end += SIGN_SIZE;
      const sign  = buffer.slice(start, end);
      // Check ID.
      const [ timestamp, node, sequence, isValid ] = explodeId(id);
      expect(isValid).to.be.true;
      expect(timestamp).to.be.a('number');
      expect(node).to.equal(1023);
      expect(sequence).to.equal(0);
      // Check verify hmac.
      const hmacVerify = crypto.createHmac(HMAC_ALGO, verifyKey3);
      const verifyBuffer = buffer.slice(0, ID_SIZE+RND_SIZE);
      const verifyCheck = hmacVerify.update(verifyBuffer).digest();
      expect([...verifyCheck.slice(0, VERIFY_SIZE)]).to.eql([...verify]);
      // Check sign hmac.
      const hmacSign = crypto.createHmac(HMAC_ALGO, signKey3);
      const signBuffer = buffer.slice(0, ID_SIZE+RND_SIZE+VERIFY_SIZE);
      const signCheck = hmacSign.update(signBuffer).digest();
      expect([...signCheck.slice(0, SIGN_SIZE)]).to.eql([...sign]);
      expect(value).to.equal('ZZZZZZZZZZ003ZZZZZZZZZZZZQ78V0XBP8V');
      expect(value.length).to.equal(35);
    });
  });
});
