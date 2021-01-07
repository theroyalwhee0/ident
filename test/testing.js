/**
 * @theroyalwhee0/ident:test/testing.js
 */

/**
 * Imports.
 */
const chai = require('chai');
const sinon = require('sinon');

/**
 * Export mocha parts so that autocomplete isn't confused.
 */
const { describe, it } = global;

/**
 * Chai.
 */
const { expect } = chai;

/**
 * Sinon.
 */
const { spy } = sinon;

/**
 * Exports.
 */
module.exports = {
  // Mocha.
  describe, it,
  // Chai.
  expect,
  // Sinon.
  spy,
};
