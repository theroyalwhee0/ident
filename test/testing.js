/**
 * @theroyalwhee0/ident:test/testing.js
 */

/**
 * Imports.
 */
const chai = require('chai');

/**
 * Export mocha parts so that autocomplete isn't confused.
 */
const { describe, it } = global;

/**
 * Chai.
 */
const { expect } = chai;

/**
 * Exports.
 */
module.exports = {
  // Mocha.
  describe, it,
  // Chai.
  expect,
};
