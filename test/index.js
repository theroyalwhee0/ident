/**
 * ident:test/index.js
 */

/**
 * Imports.
 */
const crypto = require('crypto');
const test = require('ava');
const {
    identFactory,
    packValues, buildInitialValues, buildValues, encryptValues,
  } = require('../src');

/**
 * Constants.
 */
const secret = 'Test123';
const name = 'test';
const instance = 0x9999;
const ivSecret = 'PCNkXowswAxLVEvddTIfVBAV9l8y6AJ4lR2i69xCrKE';
const hashSecret = 'CZUuRTqXZnM3WNjC2vMxcWB0SAfxStxA1Q/wSRShlhE';
const MAXUINT32 = 2 ** 32;
const SIZE = 25;
const KEYSIZE = 32;
const IVPARTIALSIZE = 4;
const IVSIZE = 16;
const HASHSIZE = 4;
const FINALSIZE = SIZE + IVPARTIALSIZE + HASHSIZE;
const EXPECTEDKEY = '0cf75f041798a8a131170f5e35f35c0224a6d14ae4444b32904ae88e2f576268';


/**
 * buildInitialValues.
 */
test('buildInitialValues: should be a function', (check) => {
  check.is(typeof buildInitialValues, 'function');
  check.is(buildInitialValues.length, 1);
});
test('buildInitialValues: should build initial values', (check) => {
  const results = buildInitialValues({ name, instance, secret });
  // Results.
  check.is(typeof results, 'object');
  const keyCount = Object.keys(results).length;
  check.is(keyCount, 4);
  // Name.
  check.is(typeof results.name, 'string');
  check.is(results.name.length, 4);
  // Instance.
  check.is(typeof results.instance, 'number');
  check.true(results.instance >= 0);
  check.true(results.instance <= MAXUINT32);
  check.is(results.instance, Math.floor(results.instance));
  // Key.
  check.true(results.key instanceof Buffer);
  check.is(results.key.length, KEYSIZE);
  check.is(results.key.toString('hex'), EXPECTEDKEY);
  // Counter.
  check.is(typeof results.counter, 'number');
  check.true(results.counter >= 0);
  check.true(results.counter <= MAXUINT32);
  check.is(results.counter, Math.floor(results.counter));
});

/**
 * buildValues.
 */
test('buildValues: should be a function', (check) => {
  check.is(typeof buildValues, 'function');
  check.is(buildValues.length, 1);
});
test('buildValues: should build per call values', (check) => {
  const results = buildValues({
    counter: 5000,
    key: Buffer.from(EXPECTEDKEY, 'hex'),
  });
  check.is(typeof results, 'object');
  check.is(results.counter, 5001);
  check.is(typeof results.random, 'number');
  check.is(typeof results.seconds, 'number');
  check.is(typeof results.nanoseconds, 'number');
});

/**
 * packValues.
 */
test('packValues: should be a function', (check) => {
  check.is(typeof packValues, 'function');
  check.is(packValues.length, 1);
});
test('packValues: should pack data correctly', (check) => {
  const results = packValues({
    name: '1234',
    instance: 0x12345678,
    counter: 0xBCDEF123,
    version: 0x45,
    seconds: 0x6789ABCD,
    nanoseconds: 0x12345678,
    random: 0x9ABCDEF1,
  });
  let idx = 0;
  // Results.
  check.true(results instanceof Buffer);
  check.is(results.length, SIZE);
  // Random.
  const randomRead = results.readUInt32BE(idx);
  idx += 4;
  check.is(randomRead, 0x9ABCDEF1);
  // Name.
  const nameRead = results.toString('ascii', idx, idx + 4);
  idx += 4;
  check.is(nameRead, '1234');
  // Instance.
  const instanceRead = results.readUInt32BE(idx);
  idx += 4;
  check.is(instanceRead, 0x12345678);
  // Counter.
  const counterRead = results.readUInt32BE(idx);
  idx += 4;
  check.is(counterRead, 0xBCDEF123);
  // Time.
  const seconds = results.readUInt32BE(idx);
  idx += 4;
  const nanoseconds = results.readUInt32BE(idx);
  idx += 4;
  check.is(seconds, 0x6789ABCD);
  check.is(nanoseconds, 0x12345678);
  // Version.
  const version = results.readUInt8(idx);
  idx += 1;
  check.is(version, 0x45);
  check.is(idx, results.length, 'buffer is too large');
});

/**
 * encryptValues.
 */
test('encryptValues: should be a function', (check) => {
  check.is(typeof encryptValues, 'function');
  check.is(encryptValues.length, 2);
});
test('encryptValues: should encrypt a buffer', (check) => {
  const INPUT = '9abcdef13132333412345678bcdef1236789abcd1234567845';
  const buffer = Buffer.from(INPUT, 'hex');
  const key = Buffer.from(EXPECTEDKEY, 'hex');
  const values = { key, buffer };
  const results = encryptValues(values, {
    hashSecret,
    ivSecret,
  });
  // Encrypt.
  check.true(results instanceof Buffer);
  check.is(results.length, FINALSIZE);
  // And be able to decrypt.
  let idx = 0;
  const ivPartial = results.slice(idx, idx + IVPARTIALSIZE);
  idx += IVPARTIALSIZE;
  check.is(ivPartial.length, IVPARTIALSIZE);
  const hash = results.slice(idx, idx + HASHSIZE);
  idx += HASHSIZE;
  check.is(hash.length, HASHSIZE);
  const iv = crypto.createHash('sha256')
    .update(ivSecret)
    .update(ivPartial)
    .digest()
    .slice(0, IVSIZE);
  const encrypted = results.slice(idx, results.length + 1);
  idx += SIZE;
  check.is(encrypted.length, SIZE);
  check.is(idx, FINALSIZE);
  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  check.is(decrypted.toString('hex'), INPUT);
  const hashVerify = crypto.createHash('sha256')
    .update(hashSecret)
    .update(encrypted)
    .update(ivPartial)
    .digest()
    .slice(0, HASHSIZE);
  check.is(hashVerify.toString('hex'), hash.toString('hex'));
});

/**
 * identFactory.
 */
test('identFactory: should be a function', (check) => {
  check.is(typeof identFactory, 'function');
  check.is(identFactory.length, 1);
});
test('identFactory: should be build a function', (check) => {
  const getIdent = identFactory({ name, secret });
  check.is(typeof getIdent, 'function');
  check.is(getIdent.length, 0);
});
test('identFactory: should generate idents', (check) => {
  const getIdent = identFactory({
    name,
    secret,
    hashSecret,
    ivSecret,
  });
  const ident1 = getIdent();
  const ident2 = getIdent();
  check.is(typeof ident1, 'string');
  check.is(ident1.length, 44);
  check.regex(ident1, /^[A-Za-z0-9+/]{44}$/);
  check.is(typeof ident2, 'string');
  check.is(ident2.length, 44);
  check.regex(ident2, /^[A-Za-z0-9+/]{44}$/);
  check.true(ident1 !== ident2);
});
test('identFactory: idents should not repeat', (check) => {
  const count = 3000;
  const getIdent = identFactory({
    name,
    secret,
    hashSecret,
    ivSecret,
  });
  const previousIdents = { };
  for (let loop = 0; loop < count; loop += 1) {
    const ident = getIdent();
    check.is(previousIdents[ident], undefined);
    previousIdents[ident] = 1;
  }
});
