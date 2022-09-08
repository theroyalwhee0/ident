/**
 * @file A Unique Identifier Generator for Node
 * @author Adam Mill <hismajesty@theroyalwhee.com>
 * @copyright Copyright 2021-2022 Adam Mill
 * @license Apache-2.0
 */

/**
 * Imports.
 * @private
 */
import crypto from 'node:crypto';
import { isString } from '@theroyalwhee0/istype';
import { idSequence, explodeId, SequenceOptions } from '@theroyalwhee0/snowman';
import { decodeBin, encodeBin } from '@base32h/base32h';
import {
  HMAC_ALGO,
  ALL_SIZE, ID_SIZE, RND_SIZE, VERIFY_SIZE, SIGN_SIZE,
  re_lax,
} from './constants';

/**
 * Default Options.
 * @private
 */
const defaultOptions = {
  getRandomBytes: (size:number) => crypto.randomBytes(size),
};

/**
 * Ident options.
 */
export type IdentOptions = {
  signKey: string,
  node?: number,
  verifyKey?: string,
  idOptions?: SequenceOptions
  getRandomBytes?: (size:number) => Buffer,
};

/**
 * Build options from options and defaults.
 * @private
 * @param {object} options The options.
 * @returns {object} The merged/modified options.
 */
function buildOptions(options:IdentOptions):IdentOptions {
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
 * @generator
 * @function identGenerator
 * @param {object} options Options.
 * @param {number} options.node The numeric ID of the node (0-1023).
 * @param {string} options.signKey The key to use for signing check.
 * @param {string} options.verifyKey The key to use for verify check.
 * @param {string} options.getRandomBytes Function to provide random bytes.
 * @param {object} options.idOptions Options passed to snowman.
 * @yields {string} The created ident.
 */
export function* identGenerator(options:IdentOptions) {
  options = buildOptions(options);
  const { verifyKey, signKey, getRandomBytes } = options;
  const ids = idSequence(options.idOptions) as Generator<bigint, bigint, void>;
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
 * @private
 * @param {Buffer} buffer A buffer to left trim.
 * @param {number} byte The byte value to trim. Defaults to zero.
 * @returns {Buffer} The trimmed buffer.
 */
function leftTrimBuffer(buffer:Buffer, byte=0) {
  let idx;
  for(idx=0; idx < buffer.length; idx++) {
    if(buffer[idx] !== byte) {
      break;
    }
  }
  return idx === 0 ? buffer : buffer.slice(idx);
}

/**
 * Low-level validation factory.
 * Use validationVerifyFactory, validationSignFactory, or
 * validationBothFactory instead.
 * @param {object} options Options.
 * @param {string} options.signKey The key to use for signing check.
 * @param {string} options.verifyKey The key to use for verify check.
 * @returns True if valid, false if not.
 */
export function validationFactory(options?:IdentOptions) {
  options = buildOptions(options);
  const { verifyKey, signKey } = options;
  return function validation(value:string) {
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
    const [ ,,, idValid ] = explodeId(id);
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
 * @param {string} options.signKey The key to use for signing check.
 * @returns {boolean} True if valid, false if not.
 */
export function validationSignFactory(options?:IdentOptions) {
  if(!options?.signKey) {
    throw new Error('signKey is required.');
  }
  return validationFactory(options);
}

/**
 * Validation factory requring a verifyKey.
 * @param {object} options Options.
 * @param {string} options.verifyKey The key to use for verify check.
 * @returns {boolean} True if valid, false if not.
 */
export function validationVerifyFactory(options?:IdentOptions) {
  if(!options?.verifyKey) {
    throw new Error('verifyKey is required.');
  }
  return validationFactory(options);
}

/**
 * Validation factory requring both keys.
 * @param {object} options Options.
 * @param {string} options.signKey The key to use for signing check.
 * @param {string} options.verifyKey The key to use for verify check.
 * @returns {boolean} True if valid, false if not.
 */
export function validationBothFactory(options?:IdentOptions) {
  if(!options?.signKey) {
    throw new Error('signKey is required.');
  }
  if(!options?.verifyKey) {
    throw new Error('verifyKey is required.');
  }
  return validationFactory(options);
}
