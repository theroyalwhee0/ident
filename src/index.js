/**
 * ident:src/index.js
 */
'use strict';

/**
 * Imports.
 */
const crypto = require('crypto');
const { hrDate } = require('@theroyalwhee0/hrdate');

/**
 * Number Size Constants.
 */
const SIZE_UINT32 = 4;

/**
 * Number Range Constants.
 */
const MIN_UINT32 = 0;
const MAX_UINT32 = 2 ** 32;


/**
 * Generate a random unsigned 32 bit integer.
 * @return {Number} The random UInt32.
 */
function randomUInt32() {
  // NOTE: It does not matter which endian is used, it is all random.
  return crypto.randomBytes(SIZE_UINT32).readUInt32BE(0);
}

/**
 * Counter factory.
 * @param  {Object} options Options.
 * @return {Function}         A counter function that increments a value and
 * returns it, wrapping around when appropriate.
 */
function counterFactory(options) {
  let value = options && options.initialCounter ? options.initialCounter : randomUInt32();
  return function counter() {
    value += 1;
    if(value > MAX_UINT32) {
      value = MIN_UINT32;
    }
    return value;
  };
}

/**
 * Convert bytes to a uint32.
 * @param  {String|Number|Undefined} value        The value to convert. May be a
 * UInt32, a ASCII string of 1 to 4 characters, or undefined.
 * @param  {Number|Undefined} defaultValue The value to return if no value was given.
 * @return {Number}              The UInt32 value.
 */
function bytesToUInt32(value, defaultValue) {
  if (value === undefined) {
    return defaultValue || 0;
  } else if(typeof value === 'string') {
    if(/^[\x00-\x7F]{1,4}$/.test(value)) {
      const padded = (value + '\0x00\0x00\0x00\0x00').substring(0, 4);
      const output = value.codePointAt(3)
        | (value.codePointAt(2) << 8)
        | (value.codePointAt(1) << 16)
        | (value.codePointAt(0) << 24);
      return output;
    } else {
      throw new Error('string "value" should be 1 to 4 ASCII characters');
    }
  } else if(typeof value === 'number') {
    if(value >= MIN_UINT32 && value <= MAX_UINT32 && value === Math.floor(value)) {
      return value;
    } else {
      throw new Error('number "value" should must be a UInt32');
    }
  } else {
    throw new Error('"value" expected to be string, undefined, or number');
  }
}

/**
 * Pack a list of UInt32s into a buffer.
 * @param  {Array<Number>} values List of UInt32s.
 * @return {Buffer}        The buffer.
 */
function packValues(values) {
  const buffer = new Buffer(values.length*4).fill(0);
  for(let idx=0; idx < values.length; idx++) {
    const value = values[idx];
    buffer.writeUInt32BE(value, idx*4);
  }
  return buffer;
}

/**
 * Encrypt and sign the values with the key.
 * @param  {[Buffer} encryptionKey Buffer with the encryption key in it.
 * @param  {Buffer} signatureKey  Buffer with the signature key in it.
 * @param  {Buffer} ivKey  Buffer with the IV key in it.
 * @param  {Buffer} buffer         The input data to encrypt.
 * @return {Buffer}               The encrypted buffer.
 */
function encryptValues(encryptionKey, signatureKey, ivKey, buffer) {
  const KEYSIZE = 32;
  const IVPARTIALSIZE = 4;
  const IVFULLSIZE = 16;
  const SIGNATURESIZE = 4;
  const ALGORITHM = 'aes-256-ctr';
  const ivPartial = crypto.randomBytes(IVPARTIALSIZE);
  const iv = crypto.createHmac('sha256', ivKey)
    .update(ivPartial)
    .digest()
    .slice(0, IVFULLSIZE);
  const cipher = crypto.createCipheriv(ALGORITHM, encryptionKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(buffer),
    cipher.final(),
  ]);
  const signaturePartial = crypto.createHmac('sha256', signatureKey)
    .update(ivPartial)
    .update(encrypted)
    .digest()
    .slice(0, SIGNATURESIZE);
  const combined = Buffer.concat([
    ivPartial,
    signaturePartial,
    encrypted,
  ]);
  return combined;
}

/**
 * Identity factory.
 * @param  {Object} options Options for identity.
 * @return {Function}      The new identity builder.
 */
function identFactory(options) {
  const encryptionKey = options.encryptionKey;
  const signatureKey = options.signatureKey;
  const ivKey = options.ivKey;
  const name = bytesToUInt32(options && options.name);
  const instance = bytesToUInt32(options && options.instance);
  const counter = counterFactory(options);
  return () => {
    const count = counter();
    const [second,nanosecond]=hrDate();
    const packed = packValues([ nanosecond, name, instance, count, second ]);
    const encrypted = encryptValues(encryptionKey, signatureKey, ivKey, packed);
    return encrypted.toString('base64').replace(/=+$/, '');
  };
}

/**
 * Exports.
 */
module.exports = {
  // Library.
  identFactory,
  // Internal Utilities, may change between versions.
  counterFactory,
  bytesToUInt32,
  packValues,
  encryptValues,
};
