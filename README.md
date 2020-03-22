# A Javascript Library for Zenroom

zenroom-lib is a javascript library to interact with the [Zenroom Virtual Machine](https://zenroom.org/)

|Package|Branch|Pipeline|Coverage|
|:-:|:-:|:-:|:-:|
[![npm version](https://badge.fury.io/js/%40caelum-tech%2Fzenroom-lib.svg)](https://badge.fury.io/js/%40caelum-tech%2Fzenroom-lib)|[`master`](https://gitlab.com/caelum-tech/Lorena/zenroom-lib/tree/master)|[![pipeline status](https://gitlab.com/caelum-tech/Lorena/zenroom-lib/badges/master/pipeline.svg)](https://gitlab.com/caelum-tech/Lorena/zenroom-lib/commits/master)|[![coverage report](https://gitlab.com/caelum-tech/Lorena/zenroom-lib/badges/master/coverage.svg)](https://gitlab.com/caelum-tech/Lorena/zenroom-lib/commits/master)|

Zenroom is a tiny and portable virtual machine that integrates in any application to authenticate and restrict access to data and execute human-readable smart contracts.

## Installation
```shell
npm install @caelum-tech/zenroom-lib
```

### For React
This library uses [Zenroom](https://www.npmjs.com/package/zenroom) 1.0.0 [which has a problem](https://www.dyne.org/using-zenroom-with-javascript-react-part3/) with [create-react-app](https://create-react-app.dev/).  To fix this issue we've added [a script](https://gitlab.com/caelum-tech/lorena/zenroom-lib/blob/master/bin/zenroom_modules.sh) which patches the installed package:
```shell
./node_modules/@caelum-tech/zenroom-lib/bin/zenroom_modules.sh
```

## Usage

Initialize
```javascript
const Zen = require('@lorena-ssi/zenroom-lib')
let z = new Zen()
```

## Keypairs

Create keypairs
```javascript
// Create a new keypair for Alice & Bob
let alice_keypair = await z.newKeyPair('Alice')
let bob_keypair = await z.newKeyPair('Bob')
```

Being the result:
```javascript
{
  zenroom: {
    curve: 'goldilocks',
    encoding: 'url64',
    version: '1.0.0+a7fab75',
    scenario: 'simple'
  },
  Alice: {
    keypair: {
      public_key: 'u64:BH4GCburF7yL1KhITA676nxKIgEB2SQZ9BmeehuoWgPObMpb9ZTTigBgfhbrwLTxf0tWtRK6kM6D0DVItqdMWGRDsII75qXcLOunQTTiGcpAH3_iTlqjzXUDeDzcudyFhZByFohsi1wCqeAXPsKsjeQ',
      private_key: 'u64:IKwYf6BRXMQBveMizlkx0k1ru3qg3wApZBAfZ2sUL6nUGKG9tvU6hB9s4cmN-Gi2rXDjeIm-quk'
    }
  }
}
```

Retrieve only the public Key
```javascript
// Create a new keypair for Alice & Bob
let alice_public = await z.publicKey('Alice', alice_keypair)
let bob_public = await z.publicKey('Bob', bob_keypair)
```

Being the result:
```javascript
{
  zenroom: {
    curve: 'goldilocks',
    encoding: 'url64',
    version: '1.0.0+a7fab75',
    scenario: 'simple'
  },
  Alice: {
    public_key: 'u64:BJeFhvqKzJERiHrZaMHlPR6ms59086qcwtafngq2nJvyDUatcdH7NSkVGvf5iKnWpsC546lTjhLIxWDf1-wfUdRy3dXa6Y6OzQvmMtqrRh33t5pXvuCDylRGiA4DqWKV6ocymggIvhdtMaXLOvNDoy4'
  }
}

```

## Signatures
Sign a message
```javascript
// Create a new keypair for Alice & Bob
const signature = await z.signMessage('Alice', alice_keypair, message)
```
Being the result:
```javascript
{
  zenroom: {
    curve: 'goldilocks',
    encoding: 'url64',
    version: '1.0.0+a7fab75',
    scenario: 'simple'
  },
  Alice: {
    draft: 'u64:SGVsbG9fV29ybGQ',
    signature: {
      s: 'u64:H71LonTCQOhhvuYCx9dMXNLDe0g-qngR28njL0tAgn8mdX2YYu2tAn9jyeaUJmBpk9iJijr7cvE',
      r: 'u64:Pv4lnBlJgPaFxEGXHntwIaUem__tjFpWQMOG9yelvb2VB5xvj2PXMTg-SsHExfL6BSPaHwFSbdo'
    }
  }
}
```

Check the signature
```javascript
// Create a new keypair for Alice & Bob
const check = await z.checkSignature('Alice', alice_public, signature, 'Bob')
```
Being the result:
```javascript
{
  zenroom: {
    curve: 'goldilocks',
    encoding: 'url64',
    version: '1.0.0+a7fab75',
    scenario: 'simple'
  },
  signature: 'correct'
}

```

## Encryption
encrypts a message
```javascript
// Create a new keypair for Alice & Bob
const msg_encrypted = await z.encryptMessage('Alice', alice_keypair, 'Bob', bob_public, 'HelloWorld')
```
Being the result:
```javascript
{
  secret_message: {
    iv: 'u64:Da57UyzCWz0gbxCeLpPPLA',
    header: 'u64:VGhpc19pc190aGVfaGVhZGVy',
    text: 'u64:4vazxwae5d4Pi9E',
    checksum: 'u64:pRGDjsiYg_9dQS1rWk-gVg'
  },
  zenroom: {
    curve: 'goldilocks',
    encoding: 'url64',
    version: '1.0.0+a7fab75',
    scenario: 'simple'
  }
}

```

Decrypts a message
```javascript
// Create a new keypair for Alice & Bob
let msg = await z.decryptMessage('Alice', alice_public, 'Bob', bob_keypair, msg_encrypted)
```
Being the result:
```javascript
{
  message: 'Hello_World',
  zenroom: {
    curve: 'goldilocks',
    encoding: 'url64',
    version: '1.0.0+a7fab75',
    scenario: 'simple'
  },
  header: 'This_is_the_header'
}
```

