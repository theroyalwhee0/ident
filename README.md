# ident
## A Unique Identity Generator for Node
Generates unique non-predictable collision-resistant identifiers using an encrypted combination of randomness, counter, time stamp, and names.
Identities will be random-looking base64 strings similar to 'rqhk9abA3U5DE4txTXwokDsiAd1mT/BXt1lvsA'.

## Example:
```
const { identFactory } = require('@theroyalwhee0/ident');
const getIdent = identFactory({
    name: 'www',
    instance: '1',
    encryptionKey: Buffer.from('wdIWvR5A3TDPYUajuVveoNSGhb40Dng4'),
    signatureKey: Buffer.from('rn7jDzzAhOcgHR9giWSLwbSFLW0N27ad'),
    ivKey: Buffer.from('oPTZXD6LN4EBUzM/7asvD6Sr40v7EceG'),
  });
const ident1 = getIdent();
const ident2 = getIdent();
console.log(`${ident1}, ${ident2}`);
```

## History
 - 0.0.1 Initial version.
