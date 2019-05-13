# DNS Stamp

This node module provides a simple API to parse and generate [DNS Stamp](https://dnscrypt.info/stamps-specifications/) as defined by [Frank Denis](https://twitter.com/jedisct1).

## Installation

    npm install node-dnsstamp

## Usage

Parse a stamp URL:

```js
const DNSStamp = require('dnsstamp');

let stamp = DNSStamp.parse(sdns);
```

Create a stamp URL:

```js
const DNSStamp = require('dnsstamp');

let stamp = new DNSStamp.DNSCrypt(addr, {
    pk: pk,
    providerName: providerName,
});
let sdns = stamp.toString();
```

## Licenses

All source code is licensed under the [MIT License](https://raw.github.com/rs/node-dnsstamp/master/LICENSE).