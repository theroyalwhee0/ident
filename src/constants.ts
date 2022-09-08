/**
 * @file A Unique Identifier Generator for Node
 * @author Adam Mill <hismajesty@theroyalwhee.com>
 * @copyright Copyright 2021-2022 Adam Mill
 * @license Apache-2.0
 */

/**
 * General.
 * @private
 */
export const HMAC_ALGO = 'sha256';

/**
 * Size constants.
 * @private
 */
export const ID_SIZE = 8;
export const RND_SIZE = 8;
export const VERIFY_SIZE = 2;
export const SIGN_SIZE = 4;
export const ALL_SIZE = ID_SIZE+RND_SIZE+VERIFY_SIZE+SIGN_SIZE;

/**
 * Validation regexp.
 * @private
 */
export const re_strict = /^[123456789ABCDEFGHJKLMNPQRTVWXYZ][0123456789ABCDEFGHJKLMNPQRTVWXYZ]+$/;
export const re_lax = /^[0-9A-Za-z]+$/;
