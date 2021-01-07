/**
 * @theroyalwhee0/ident:src/constants.js
 */

/**
 * General.
 */
const HMAC_ALGO = 'sha256';

/**
 * Size constants.
 */
const ID_SIZE = 8;
const RND_SIZE = 8;
const VERIFY_SIZE = 2;
const SIGN_SIZE = 4;
const ALL_SIZE = ID_SIZE+RND_SIZE+VERIFY_SIZE+SIGN_SIZE;

/**
 * Validation regexp.
 */
const re_strict = /^[123456789ABCDEFGHJKLMNPQRTVWXYZ][0123456789ABCDEFGHJKLMNPQRTVWXYZ]+$/;
const re_lax = /^[0-9A-Za-z]+$/;

/**
 * Exports.
 */
module.exports = {
  // General.
  HMAC_ALGO,
  // Sizes.
  ALL_SIZE, ID_SIZE, RND_SIZE, VERIFY_SIZE, SIGN_SIZE,
  // RegExp.
  re_strict, re_lax,
};
