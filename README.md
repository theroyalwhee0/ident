# @theroyalwhee0/ident

## A Unique Identity/Token Generator for Node
Generates unique non-predictable distributed identifiers.
It is built from a combination of a [snowflake ID](https://github.com/theroyalwhee0/snowman/), random bytes, and two partial HMACs. It is encoded using [base32h](https://base32h.github.io/).


## Installation
npm install @theroyalwhee0/ident

*or*

yarn add @theroyalwhee0/ident


## Documentation
The identGenerator() function creates a iterable sequence of tokens. The validation*Factory() functions validates a given token's structure and check the partial HMAC values.

[API Documentation](https://theroyalwhee0.github.io/ident/)


## Usage
```
const { identGenerator, validationBothFactory } = require('@theroyalwhee0/ident');
const verifyKey = 'bird';
const signKey = 'seed';
const idents = identGenerator({
    node: 1,
    verifyKey, signKey,
  });
const validate = validationBothFactory({
    verifyKey, signKey,
  });
const { value: ident1 } = idents.next();
const { value: ident2 } = idents.next();
console.log(`${ident1}, ${ident2}`);
console.log(`${validate(ident1)}, ${validate(ident2)}`);
```

## Testing.
Running ```npm run test``` will run the test suite under Mocha. Running ```npm run test-watch``` will run the test suite in watch mode.


## Links
- GitHub: https://github.com/theroyalwhee0/ident/
- NPM: https://www.npmjs.com/package/@theroyalwhee0/ident/


## History
- v1.0.4 - 2021-02-14
  - Bump version of snowman.
  - Remove dates from documentation.
- v1.0.3 - 2021-02-06
  - Bump version of snowman.
- v1.0.2 - 2021-02-04
  - Add documentation.
  - Upgrade depends, fix deprecated references.
  - Remove unused dev depends.
- v1.0.1 - 2021-01-29
  - Upgrade to latest version of [@theroyalwhee0/snowman](https://www.npmjs.com/package/@theroyalwhee0/snowman/)
- v1.0.0 - 2021-01-07
  - Initial release of v1 library.

 Previous versions are a different unsupported library that shares the same name.


## Legal & License
Copyright 2020-2021 Adam Mill

This library is released under Apache 2 license. See [LICENSE](https://github.com/theroyalwhee0/ident/blob/master/LICENSE) for more details.
