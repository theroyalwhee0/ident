/**
 * @theroyalwhee0/ident:src/index.js
 */

/**
 * Imports.
 */
const crypto = require('crypto');
const { isString } = require('@theroyalwhee0/istype');
const { idSequence, explode } = require('@theroyalwhee0/snowman');
const { decodeBin, encodeBin } = require('@base32h/base32h');
const {
  HMAC_ALGO,
  ALL_SIZE, ID_SIZE, RND_SIZE, VERIFY_SIZE, SIGN_SIZE,
  re_lax,
} = require('./constants');

/**
 * Default Options.
 */
const defaultOptions = {
  getRandomBytes: (size) => crypto.randomBytes(size),
};

/**
 * Build options from options and defaults.
 * @param {object} options
 */
function buildOptions(options) {
  const built = Object.assign({}, defaultOptions, options);
  const idOptions = Object.assign({}, built.idOptions);
  built.idOptions = idOptions;
  if('node' in built) {
    idOptions.node = built.node;
  }
  return built;
}

/**
 * identGenerator
 */
function* identGenerator(options) {
  options = buildOptions(options);
  const { verifyKey, signKey, getRandomBytes } = options;
  const ids = idSequence(options.idOptions);
  while(1) {
    // Create the buffer.
    const buffer = Buffer.alloc(ALL_SIZE, 0);
    // Add the id.
    const { value: id, done } = ids.next();
    if(done) {
      throw new Error(`id sequence should never be done.`);
    }
    buffer.writeBigUInt64BE(id, 0);
    // Add the random bytes.
    const rnd = getRandomBytes(RND_SIZE);
    rnd.copy(buffer, ID_SIZE, 0, RND_SIZE);
    // Add verification hmac.
    const verifyBuffer = buffer.slice(0, ID_SIZE+RND_SIZE);
    const hmacVerify = crypto.createHmac(HMAC_ALGO, verifyKey);
    const verify = hmacVerify.update(verifyBuffer).digest();
    verify.copy(buffer, ID_SIZE+RND_SIZE, 0, VERIFY_SIZE);
    // Add signature hmac.
    const signBuffer = buffer.slice(0, ID_SIZE+RND_SIZE+VERIFY_SIZE);
    const hmacSign = crypto.createHmac(HMAC_ALGO, signKey);
    const sign = hmacSign.update(signBuffer).digest();
    sign.copy(buffer, ID_SIZE+RND_SIZE+VERIFY_SIZE, 0, SIGN_SIZE);
    // Encode buffer and strip leading zeros.
    const ident = encodeBin(buffer).replace(/^0+/, '');
    yield ident;
  }
}

/**
 * Left trim buffer.
 */
function leftTrimBuffer(buffer, byte=0) {
  let idx;
  for(idx=0; idx < buffer.length; idx++) {
    if(buffer[idx] !== byte) {
      break;
    }
  }
  return idx === 0 ? buffer : buffer.slice(idx);
}

/**
 * Validation factory.
 * @param {object} options Options.
 * @returns True if valid, false if not.
 */
function validationFactory(options) {
  options = buildOptions(options);
  const { verifyKey, signKey } = options;
  return function validation(value) {
    if(!isString(value) || !re_lax.test(value)) {
      return false;
    }
    const decoded = leftTrimBuffer(Buffer.from(decodeBin(value)));
    const buffer = decoded.length < ALL_SIZE ?
      Buffer.concat([ Buffer.alloc(ALL_SIZE-decoded.length, 0), decoded ])
      : decoded;
    if(buffer.length !== ALL_SIZE) {
      return false;
    }
    let start = 0, end = ID_SIZE;
    const id = buffer.readBigUInt64BE();
    // Check ID.
    const [ ,,, idValid ] = explode(id);
    if(!idValid) {
      return false;
    }
    start = end; end += RND_SIZE;
    start = end; end += VERIFY_SIZE;
    const verify = buffer.slice(start, end);
    start = end; end += SIGN_SIZE;
    const sign = buffer.slice(start, end);
    if(verifyKey) {
      // Check verify hmac if given verify key...
      const hmacVerify = crypto.createHmac(HMAC_ALGO, verifyKey);
      const verifyBuffer = buffer.slice(0, ID_SIZE+RND_SIZE);
      const verifyCheck = hmacVerify.update(verifyBuffer).digest().slice(0, VERIFY_SIZE);
      if(!crypto.timingSafeEqual(verify, verifyCheck)) {
        return false;
      }
    }
    if(signKey) {
      // Check sign hmac if given sign key...
      const hmacSign = crypto.createHmac(HMAC_ALGO, signKey);
      const signBuffer = buffer.slice(0, ID_SIZE+RND_SIZE+VERIFY_SIZE);
      const signCheck = hmacSign.update(signBuffer).digest().slice(0, SIGN_SIZE);
      if(!crypto.timingSafeEqual(sign, signCheck)) {
        return false;
      }
    }
    return true;
  };
}

/**
 * Validation factory requring a signKey.
 * @param {object} options Options.
 * @returns True if valid, false if not.
 */
function validationSignFactory(options) {
  if(!(options && options.signKey)) {
    throw new Error('signKey is required.');
  }
  return validationFactory(options);
}

/**
 * Validation factory requring a verifyKey.
 * @param {object} options Options.
 * @returns True if valid, false if not.
 */
function validationVerifyFactory(options) {
  if(!(options && options.verifyKey)) {
    throw new Error('verifyKey is required.');
  }
  return validationFactory(options);
}

/**
 * Validation factory requring both keys.
 * @param {object} options Options.
 * @returns True if valid, false if not.
 */
function validationBothFactory(options) {
  if(!(options && options.signKey)) {
    throw new Error('signKey is required.');
  }
  if(!(options && options.verifyKey)) {
    throw new Error('verifyKey is required.');
  }
  return validationFactory(options);
}

/**
 * Exports.
 */
module.exports = {
  identGenerator,
  validationFactory,
  validationSignFactory,
  validationVerifyFactory,
  validationBothFactory,
};
