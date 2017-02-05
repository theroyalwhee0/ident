/**
 * ident:src/index.js
 */
/* eslint no-param-reassign: ["error", { "props": false }] */

/**
 * Imports.
 */
const crypto = require('crypto');
const { hrDate } = require('@theroyalwhee0/hrdate');

/**
 * Constants.
 */
const S_UINT8 = 1;
const S_UINT32 = 4;
const ALGORITHM = 'aes-256-ctr';
const SIZE = 25; // Bytes.
const IVPARTIALSIZE = 4;
const IVSIZE = 16;
const KEYSIZE = 32;
const HASHSIZE = 4;
const KEYITERATIONS = 100000;
const KEYDIGEST = 'sha256';

/**
 * Build initial values.
 */
function buildInitialValues(options) {
  // Name.
  const name = options.name;
  // Name.
  const instance = options.instance || 1;
  // Key.
  const iterations = options.iterations || KEYITERATIONS;
  const key = crypto.pbkdf2Sync(options.secret, options.name, iterations, KEYSIZE, KEYDIGEST);
  // Counter.
  const counter = crypto.randomBytes(S_UINT32).readUInt32BE(0);
  return {
    name,
    instance,
    key,
    counter,
  };
}

/**
 * Build values from initial values and add new values.
 */
function buildValues(initial) {
  // Counter.
  initial.counter += 1;
  // Time.
  const [seconds, nanoseconds] = hrDate();
  // Random.
  const random = crypto.randomBytes(S_UINT32).readUInt32BE(0);
  return Object.assign({ }, initial, {
    random,
    seconds,
    nanoseconds,
  });
}

/**
 * Encrypt the values with the key.
 * @param  {[type]} value   [description]
 * @param  {[type]} options [description]
 * @return {[type]}             [description]
 */
function encryptValues(values, options) {
  const buffer = values.buffer;
  const key = values.key;
  const ivPartial = crypto.randomBytes(IVPARTIALSIZE);
  const iv = crypto.createHash('sha256')
    .update(options.ivSecret)
    .update(ivPartial)
    .digest()
    .slice(0, IVSIZE);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(buffer),
    cipher.final(),
  ]);
  const hash = crypto.createHash('sha256')
    .update(options.hashSecret)
    .update(encrypted)
    .update(ivPartial)
    .digest()
    .slice(0, HASHSIZE);
  const full = Buffer.concat([
    ivPartial,
    hash,
    encrypted,
  ]);
  return full;
}

/**
 * packValues
 */
function packValues(values) {
  let idx = 0;
  // Buffer.
  const buffer = new Buffer(SIZE).fill(0x55);
  // Random.
  buffer.writeUInt32BE(values.random, idx);
  idx += S_UINT32;
  // Name.
  buffer.write(values.name, idx, 4, 'ascii');
  idx += 4;
  // Instance.
  buffer.writeUInt32BE(values.instance, idx);
  idx += S_UINT32;
  // Counter.
  buffer.writeUInt32BE(values.counter, idx);
  idx += S_UINT32;
  // Time, Seconds.
  buffer.writeUInt32BE(values.seconds, idx);
  idx += S_UINT32;
  // Time, Nanoseconds.
  buffer.writeUInt32BE(values.nanoseconds, idx);
  idx += S_UINT32;
  // Version.
  buffer.writeUInt8(values.version, idx);
  idx += S_UINT8;
  return buffer;
}

/**
 * Identity factory.
 * @param  {Object} options Options for identity.
 * @return {Function}      The new identity builder.
 */
function identFactory(options) {
  const opts = Object.assign({ }, options);
  const initial = buildInitialValues(opts);
  return () => {
    const values = buildValues(initial, opts);
    values.buffer = packValues(values, opts);
    const encrypted = encryptValues(values, opts);
    return encrypted.toString('base64').replace(/=+$/, '');
  };
}

/**
 * Exports.
 */
module.exports = {
  identFactory,
  buildValues,
  buildInitialValues,
  packValues,
  encryptValues,
};
