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
    counterFactory,
    bytesToUInt32,
    packValues,
    encryptValues,
  } = require('../src');

/**
 * Number Values Constants.
 */
const MIN_UINT32 = 0;
const MAX_UINT32 = 2 ** 32;

/**
 * Options.
 */
const options1 = {
  name: 'cat',
  instance: 'meow',
  encryptionKey: Buffer.from('wdIWvR5A3TDPYUajuVveoNSGhb40Dng4'),
  signatureKey: Buffer.from('rn7jDzzAhOcgHR9giWSLwbSFLW0N27ad'),
  ivKey: Buffer.from('oPTZXD6LN4EBUzM/7asvD6Sr40v7EceG'),
};


/**
 * bytesToUInt32.
 */
test('bytesToUInt32: should be a function', (check) => {
  check.is(typeof bytesToUInt32, 'function');
  check.is(bytesToUInt32.length, 2);
});
test('bytesToUInt32: should return default if no value given', (check) => {
  const results1 = bytesToUInt32(undefined, 10000);
  check.is(typeof results1, 'number');
  check.is(results1, 10000);
  const results2 = bytesToUInt32();
  check.is(typeof results2, 'number');
  check.is(results2, 0);
});
test('bytesToUInt32: should return value for a UInt32', (check) => {
  const results = bytesToUInt32(9999);
  check.is(typeof results, 'number');
  check.is(results, 9999);
});
test('bytesToUInt32: should throw if numeric value is out of range', (check) => {
  const error = check.throws(() => {
    bytesToUInt32(-8484);
  });
  check.is(error.message, 'number "value" should must be a UInt32');
});
test('bytesToUInt32: should return value for a 4 character string', (check) => {
  const results = bytesToUInt32('\x13\x14\x15\x16');
  check.is(typeof results, 'number');
  check.is(results, 0x13141516);
});
test('bytesToUInt32: should return value for a padded character string', (check) => {
  const results = bytesToUInt32('\x27\x28');
  check.is(typeof results, 'number');
  check.is(results, 0x27280000);
});
test('bytesToUInt32: should throw if string value is out of range', (check) => {
  const error = check.throws(() => {
    bytesToUInt32('thisistoolong');
  });
  check.is(error.message, 'string "value" should be 1 to 4 ASCII characters');
});

/**
 * encryptValues.
 */
test('encryptValues: should be a function', (check) => {
  check.is(typeof encryptValues, 'function');
  check.is(encryptValues.length, 4);
});
test('encryptValues: should encrypt a buffer', (check) => {
  const IVPARTIALSIZE = 4;
  const SIGNATURESIZE = 4;
  const IVFULLSIZE = 16;
  const ALGORITHM = 'aes-256-ctr';
  const input = '9abcdef13132333412345678bcdef1236789abcd1234567845';
  const encryptionKey = options1.encryptionKey;
  const signatureKey = options1.signatureKey;
  const ivKey = options1.ivKey;
  const inputBuffer = Buffer.from(input);
  const results = encryptValues(encryptionKey, signatureKey, ivKey, inputBuffer);
  // Encrypt.
  check.true(results instanceof Buffer);
  check.is(results.length, input.length + IVPARTIALSIZE + SIGNATURESIZE);
  // And be able to decrypt.
  let idx = 0;
  // IV.
  const ivPartial = results.slice(idx, idx + IVPARTIALSIZE);
  idx += IVPARTIALSIZE;
  check.is(ivPartial.length, IVPARTIALSIZE);
  const iv = crypto.createHmac('sha256', ivKey)
    .update(ivPartial)
    .digest()
    .slice(0, IVFULLSIZE);
  check.is(iv.length, IVFULLSIZE);
  // Signature.
  const signaturePartial = results.slice(idx, idx + SIGNATURESIZE);
  idx += SIGNATURESIZE;
  check.is(signaturePartial.length, SIGNATURESIZE);
  // Contents.
  const encrypted = results.slice(idx, results.length);
  check.is(encrypted.length, input.length);
  const decipher = crypto.createDecipheriv(ALGORITHM, encryptionKey, iv);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  check.is(decrypted.toString(), input);
  // Verify Signature.
  const signatureVerify = crypto.createHmac('sha256', signatureKey)
    .update(ivPartial)
    .update(encrypted)
    .digest()
    .slice(0, SIGNATURESIZE);
  check.is(signaturePartial.toString('hex'), signatureVerify.toString('hex'));
});

/**
 * counterFactory.
 */
test('counterFactory: should be a function', (check) => {
  check.is(typeof counterFactory, 'function');
  check.is(counterFactory.length, 1);
});
test('counterFactory: should be build a function', (check) => {
  const counter = counterFactory();
  check.is(typeof counter, 'function');
  check.is(counter.length, 0);
  const results = counter();
  check.is(typeof results, 'number');
  check.is(Math.floor(results), results);
  check.true(results >= MIN_UINT32 && results <= MAX_UINT32);
});
test('counterFactory: counter() should increment on each call', (check) => {
  const counter = counterFactory({ initialCounter: 1000 });
  const results1 = counter();
  check.is(results1, 1001);
  const results2 = counter();
  check.is(results2, 1002);
  const results3 = counter();
  check.is(results3, 1003);
});
test('counterFactory: counter() should wrap around', (check) => {
  const counter = counterFactory({ initialCounter: MAX_UINT32 - 2 });
  const results1 = counter();
  check.is(results1, MAX_UINT32 - 1);
  const results2 = counter();
  check.is(results2, MAX_UINT32);
  const results3 = counter();
  check.is(results3, MIN_UINT32);
  const results4 = counter();
  check.is(results4, MIN_UINT32 + 1);
});

/**
 * packValues.
 */
test('packValues: should be a function', (check) => {
  check.is(typeof packValues, 'function');
  check.is(packValues.length, 1);
});
test('packValues: should pack data correctly', (check) => {
  const results = packValues([
    0x12345678,
    0xBCDEF123,
    0x6789ABCD,
    0x12345678,
  ]);
  // Results.
  check.true(results instanceof Buffer);
  check.is(results.length, 16);
  // Random.
  const resultsHex = results.toString('hex');
  check.is(resultsHex, '12345678BCDEF1236789ABCD12345678'.toLowerCase());
});

/**
 * identFactory.
 */
test('identFactory: should be a function', (check) => {
  check.is(typeof identFactory, 'function');
  check.is(identFactory.length, 1);
});
test('identFactory: should be build a function', (check) => {
  const ident = identFactory(options1);
  check.is(typeof ident, 'function');
  check.is(ident.length, 0);
});
test('identFactory: should build an ident', (check) => {
  const ident = identFactory(options1);
  const results = ident();
  check.is(typeof results, 'string');
  check.regex(results, /^[a-zA-Z0-9+/]{38}$/);
});
test('identFactory: idents should not repeat', (check) => {
  const count = 5000;
  const ident = identFactory(options1);
  const previousIdents = { };
  for (let loop = 0; loop < count; loop += 1) {
    const value = ident();
    check.is(previousIdents[value], undefined);
    previousIdents[value] = 1;
  }
});
