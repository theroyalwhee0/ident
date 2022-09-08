import { describe, it } from 'mocha';
import { expect } from 'chai';
import {
  validationFactory,
  validationSignFactory,
  validationVerifyFactory,
  validationBothFactory,
} from '../src/index';

/**
 * Test constants.
 */
// Set One
const verifyKey1 = 'banana1';
const signKey1 = 'apple1';
// Set Two
const signKey2 = '';
const verifyKey2 = '';
// Set Three
const signKey3   = 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ';
const verifyKey3 = 'YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY';


/**
 * Tests.
 */
describe('@theroyalwhee0/ident', () => {
  describe('validationFactory', () => {
    it('should be a function', () => {
      expect(validationFactory).to.be.a('function');
      expect(validationFactory.length).to.equal(1);
    });
    it('should create a validation function', () => {
      const validation = validationFactory();
      expect(validation).to.be.a('function');
      expect(validation.length).to.equal(1);
    });
    describe('should reject invalid values', () => {
      it('with a corrupted sign hash', () => {
        const validation = validationFactory({
          signKey: signKey3, verifyKey: verifyKey3,
        });
        // Replaced last V with an X.
        const valid = validation('ZZZZZZZZZZ003ZZZZZZZZZZZZQ78V0XBP8X');
        expect(valid).to.be.false;
      });
      it('with an invalid id part', () => {
        const validation = validationFactory({
          signKey: signKey2, verifyKey: verifyKey2,
        });
        const valid = validation('5Z4E04VFQH');
        expect(valid).to.be.false;
      });
      it('given the wrong sign key', () => {
        // This ident was made with key set 3.
        const validation = validationFactory({
          signKey: 'blarg', verifyKey: verifyKey3,
        });
        const valid = validation('ZZZZZZZZZZ003ZZZZZZZZZZZZQ78V0XBP8V');
        expect(valid).to.be.false;
      });
      it('given the wrong verify key', () => {
        // This ident was made with key set 3.
        const validation = validationFactory({
          signKey: signKey3, verifyKey: 'blah',
        });
        const valid = validation('ZZZZZZZZZZ003ZZZZZZZZZZZZQ78V0XBP8V');
        expect(valid).to.be.false;
      });
    });
    describe('should accept valid values', () => {
      it('like "ZZZZZZZZZZ003ZZZZZZZZZZZZQ78V0XBP8V"', () => {
        const validation = validationFactory({
          signKey: signKey3, verifyKey: verifyKey3,
        });
        const valid = validation('ZZZZZZZZZZ003ZZZZZZZZZZZZQ78V0XBP8V');
        expect(valid).to.be.true;
      });
      it('like "1000000000000000005Z4F3HZMWV"', () => {
        const validation = validationFactory({
          signKey: signKey2, verifyKey: verifyKey2,
        });
        const valid = validation('1000000000000000005Z4F3HZMWV');
        expect(valid).to.be.true;
      });
      it('with leading zeros', () => {
        const validation = validationFactory({
          signKey: signKey2, verifyKey: verifyKey2,
        });
        const valid = validation('0oO0O0o0o01000000000000000005Z4F3HZMWV');
        expect(valid).to.be.true;
      });
      it('generated previously', () => {
        const idents = [
          'XY1A4ZG0000BP53W24CP33MKZ0VJN2ANDE',
          'XY1A4ZH000025MXXG3271X5KYX07GDGY1Q',
          'XY1A4ZH0000673BM8M0K18YFF24KV7ZG44',
          'XY1A4ZJ0000330CH8DM2N09BA4M9D2L7NL',
          'XY1A4ZK000027EDEGKMEHMZ1KYTHVWNE55',
          'XY1A4ZL00003B1HWMB93QYWGMHENVBW4KW',
          'XY1A4PZ00003880Z6WPNDGY2HYBQQB7VQ3',
          'XY1A4PZ00006TE4A2GJQYZY629T090Q1P1',
          'XY1A4Q0000038PKWJF5Z4TKPFJ9AETYF3J',
          'XY1A4J00000509ZT4V3XXCVHGAZBK5GVT3',
          'XY1A4J100003W7A5MHCAAWENFQ3G2ZJ7Q1',
        ];
        for(let idx=0; idx < idents.length; idx++) {
          const ident = idents[idx];
          const validation = validationFactory({
            signKey: signKey1, verifyKey: verifyKey1,
          });
          const valid = validation(ident);
          expect(valid).to.be.true;
        }
      });
    });
  });
  describe('validationSignFactory', () => {
    it('should be a function', () => {
      expect(validationSignFactory).to.be.a('function');
      expect(validationSignFactory.length).to.equal(1);
    });
    it('should throw if not given key', () => {
      expect(() => {
        validationSignFactory();
      }).to.throw(/signKey is required/i);
    });
  });
  describe('validationVerifyFactory', () => {
    it('should be a function', () => {
      expect(validationVerifyFactory).to.be.a('function');
      expect(validationVerifyFactory.length).to.equal(1);
    });
    it('should throw if not given key', () => {
      expect(() => {
        validationVerifyFactory();
      }).to.throw(/verifyKey is required/i);
    });
  });
  describe('validationBothFactory', () => {
    it('should be a function', () => {
      expect(validationBothFactory).to.be.a('function');
      expect(validationBothFactory.length).to.equal(1);
    });
    it('should throw if not given keys', () => {
      expect(() => {
        validationBothFactory();
      }).to.throw(/signKey is required/i);
      expect(() => {
        validationBothFactory({ signKey: 'grape1' });
      }).to.throw(/verifyKey is required/i);
    });
  });
});
