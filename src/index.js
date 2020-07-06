'use strict'
const zenroom = require('zenroom')

/**
 * returns the digital Root
 *
 * @param {number} n Number
 * @returns {number} Digital Root (1 digit)
 */
function digitalRoot (n) {
  return (n - 1) % 9 + 1
}

/**
 * Javascript Class to interact with Zenroom.
 */
module.exports = class Zen {
  constructor (silent = false) {
    this.isSilent = silent
    if (this.isSilent) {
      this.ogWriteStdout = process.stdout.write.bind(process.stdout)
      this.ogWriteStdErr = process.stderr.write.bind(process.stderr)
      /* istanbul ignore next */
      process.on('uncaughtException', function (err) {
        /* istanbul ignore next */
        console.error((err && err.stack) ? err.stack : err)
      })
    }
  }

  /**
   * Executes Zencode.
   *
   * @param {object} keys  Input keys.
   * @param {string} script Zencode to be executed
   * @param {Buffer=} paramData (optional) data to be encrypted
   * @returns {Promise} Return a promise with the execution of the script.
   */
  async execute (keys, script, paramData = undefined) {
    const options = { verbosity: 0 }

    return new Promise((resolve, reject) => {
      const log = []
      if (this.isSilent) {
        /* istanbul ignore next */
        this.stdoutWrite = (data) => log.push({ stdout: data })
        this.stderrWrite = (data) => log.push({ stderr: data })
        process.stdout.write = this.stdoutWrite
        process.stderr.write = this.stderrWrite // TODO: They need to implement verbosity https://github.com/DECODEproject/Zenroom/blob/master/bindings/javascript/src/wrapper.js
      }
      zenroom
        .init(options)
        .keys(keys)
        .data(paramData)
        .script(script)
        .print((msg) => {
          resolve(JSON.parse(msg))
        })
        .error(() => {
          reject(new Error('Zenroom error' + log))
        })
        .zencode_exec()
      if (this.isSilent) {
        process.stdout.write = this.ogWriteStdout
        process.stderr.write = this.ogWriteStdErr
      }
    })
  }

  /**
   * Creates a new keypair.
   *
   * @param {string} name  Holder of the keypair.
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async newKeyPair (name) {
    return this.execute(false,
      `rule check version 1.0.0
      Scenario simple: Create the keypair
      Given that I am known as '` + name + `'
      When I create the keypair
      Then print my data`
    )
  }

  /**
   * Creates a new keypair.
   *
   * @param {string} name  Holder of the keypair.
   * @param {*} keys to create
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async publicKey (name, keys) {
    return this.execute(keys,
      `rule check version 1.0.0
      Scenario simple Create the keypair
      Given that I am known as '` + name + `'
      and I have my valid 'public key'
      Then print my data`
    )
  }

  /**
   * Encrypts (asymmetric) a message with a keypair.
   *
   * @param {string} fromName Who's signing the message.
   * @param {object} fromKeys Keypair for the encrypter (Zencode format)
   * @param {string} toName Who's receiving the message.
   * @param {object} toKeys Public Key for the receiver (Zencode format)
   * @param {string} message Message to be encrypted
   * @returns {Promise} Return a promise with the execution of the encryption.
   */
  async encryptAsymmetric (fromName, fromKeys, toName, toKeys, message) {
    // Move to Hex.
    const msg = Buffer.from(message, 'utf8')
    return this.execute([fromKeys, toKeys],
      `Rule check version 1.0.0
      Scenario 'simple': ${fromName} sends a secret to ${toName}
      Given that I am known as '${fromName}'
      and I have my valid 'keypair'
      and I have a valid 'public key' from '` + toName + `'
      When I write string '${msg.toString('hex')}' in 'message'
      and I write string 'Header for encryption' in 'header'
      and I encrypt the message for '${toName}'
      Then print the 'secret_message'`,
      msg
    )
  }

  /**
   * Decrypts (asymmetric) a message with a keypair.
   *
   * @param {string} fromName Who's signing the message.
   * @param {object} fromKeys Keypair for the encrypter (Zencode format)
   * @param {string} toName Who's receiving the message.
   * @param {object} toKeys Public Key for the receiver (Zencode format)
   * @param {string} message Message to be decrypted
   * @returns {Promise} Return a promise with the execution of the encryption.
   */
  async decryptAsymmetric (fromName, fromKeys, toName, toKeys, message) {
    return new Promise((resolve) => {
      this.execute([fromKeys, toKeys, message],
        `Rule check version 1.0.0
        Scenario simple: ` + toName + ' decrypts the message for ' + fromName + `
        Given that I am known as '` + toName + `'
        and I have my valid 'keypair'
        and I have a valid 'public key' from '` + fromName + `'
        and I have a valid 'secret_message'
        When I decrypt the secret message from '` + fromName + `'
        Then print as 'string' the 'message'
        and print as 'string' the 'header' inside 'secret message'`
      ).then((msg) => {
        const txt = Buffer.from(msg.message, 'hex')
        resolve({
          message: txt.toString('utf8')
        })
      })
    })
  }

  /**
   * Encrypts (symmetric) a message with a keypair.
   *
   * @param {string} password Password to encrypt the message
   * @param {string} message Message to be encrypted
   * @param {string} header Header to be included
   * @returns {Promise} Return a promise with the execution of the encryption.
   */
  async encryptSymmetric (password, message, header) {
    // Move to Hex.
    // const secret = { message: Buffer.from(message, 'hex').toString() }
    const hdr = Buffer.from(header, 'utf8')

    // Encrypt.
    const data = { message: Buffer.from(message, 'utf8').toString('hex') }
    return this.execute(false,
        `
        Scenario simple: Encrypt a message with the password
        Given that I have a 'message'
        When I write string '${password}' in 'password'
        and I write string '${hdr.toString('hex')}' in 'header'
        and I encrypt the secret message 'message' with 'password'
        Then print all data`, data
    )
  }

  /**
   * Decrypts (symmetric) a message with a keypair.
   *
   * @param {string} password Password to decrypt the message
   * @param {string} msgEncrypted Message to be decrypted
   * @returns {Promise} Return a promise with the execution of the encryption.
   */
  async decryptSymmetric (password, msgEncrypted) {
    return new Promise((resolve) => {
      this.execute([msgEncrypted],
        `Rule check version 1.0.0
        Scenario simple: Decrypt the message with the password
        Given I have a valid 'secret message'
        When I write string '${password}' in 'password'
        and I decrypt the secret message with 'password'
        Then print as 'string' the 'text' inside 'message'
        and print as 'string' the 'header' inside 'message'`
      ).then((msg) => {
        const txt = Buffer.from(msg.text, 'hex')
        const hdr = Buffer.from(msg.header, 'hex')
        resolve({
          header: hdr.toString(),
          message: txt.toString()
        })
      }).catch(_e => {
        resolve(false)
      })
    })
  }

  /**
   * Signs a message with a keypair.
   *
   * @param {string} signer Who's signing the message.
   * @param {object} keys Keypair for the signer (Zencode format)
   * @param {string} message Message to be signed
   * @returns {Promise} Returns a promise with the execution of the signature.
   */
  async signMessage (signer, keys, message) {
    return this.execute(keys,
      `Rule check version 1.0.0
      Scenario simple: ` + signer + ` signs a message for Recipient
      Given that I am known as '` + signer + `'
      and I have my valid 'keypair'
      When I write string '${message}' in 'draft'
      and I create the signature of 'draft'
      Then print my 'signature'
      and print my 'draft'`
    )
  }

  /**
   * Checks signature of a message.
   *
   * @param {string} signer Who's signing the message.
   * @param {object} signerPublic Who's signing the message, public Key.
   * @param {object} signature Signature of the message.
   * @param {string} verifier Message to be checked
   * @returns {Promise} Returns a promise with the execution of the signature.
   */
  async checkSignature (signer, signerPublic, signature, verifier) {
    const checkScript = `
      rule check version 1.0.0
      Scenario simple: ` + verifier + ' verifies the signature from ' + signer + `
      Given that I am known as '` + verifier + `'
      and I have a valid 'public key' from '` + signer + `'
      and I have a valid 'signature' from '` + signer + `'
      and I have a 'draft'
      When I verify the 'draft' is signed by '` + signer + `'
      Then print 'signature' 'correct' as 'string'`
    const keys = signature
    keys[signer].public_key = signerPublic[signer].public_key
    return this.execute(keys, checkScript)
  }

  /**
   * Creates a new Issuer keypair.
   *
   * @param {string} name  Issuer of the credential keypair.
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async newIssuerKeyPair (name) {
    return this.execute(false, `rule check version 1.0.0
    Scenario 'coconut': issuer keygen
    Given that I am known as '` + name + `'
    When I create the issuer keypair
    Then print my 'issuer keypair'`)
  }

  /**
   * ZKP : Get the Verifier to be published.
   *
   * @param {string} verifier Who's signing the message.
   * @param {object} keys Keypair for the signer (Zencode format)
   * @returns {Promise} Returns a promise with the execution of the signature.
   */
  async publishVerifier (verifier, keys) {
    return this.execute(keys,
      `rule check version 1.0.0
      Scenario 'coconut': publish verifier
      Given that I am known as '` + verifier + `'
      and I have a valid 'verifier'
      Then print my 'verifier'`
    )
  }

  /**
   * Creates a new Credential keypair.
   *
   * @param {string} name  Holder of the keypair.
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async newCredentialKeyPair (name) {
    const keygenContract = `rule check version 1.0.0
      Scenario 'coconut': issuer keygen
        Given that I am known as '` + name + `'
        When I create the credential keypair
        Then print my 'credential keypair'`
    return this.execute(false, keygenContract)
  }

  /**
   * Creates a new Signature Request.
   *
   * @param {string} name  Holder of the credential.
   * @param {object} credentialKeyPair Keypair for the credentials (Zencode format)
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async credentialSignatureRequest (name, credentialKeyPair) {
    return this.execute(credentialKeyPair, `rule check version 1.0.0
      Scenario 'coconut': create request
      Given that I am known as '` + name + `'
      and I have my valid 'credential keypair'
      When I create the credential request
      Then print my 'credential request'`)
  }

  /**
   * Creates a new Credential keypair.
   *
   * @param {string} nameIssuer  Issuer of the credential.
   * @param {object} issuerKeyPair Keypair for the Issuer (Zencode format)
   * @param {object} signatureRequest signature Request by the Credential Holder.
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async signCredentialSignatureRequest (nameIssuer, issuerKeyPair, signatureRequest) {
    return this.execute([issuerKeyPair, signatureRequest],
      `rule check version 1.0.0
      Scenario 'coconut': issuer sign
      Given that I am known as '` + nameIssuer + `'
      and I have my valid 'issuer keypair'
      and I have a valid 'credential request'
      When I create the credential signature
      Then print the 'credential signature'
      and print the 'verifier'`
    )
  }

  /**
   * Aggregates signature to the credential Proof.
   *
   * @param {string} name  Holder of the keypair.
   * @param {object} credentialKeyPair Keypair for the credentials (Zencode format)
   * @param {object} credentialSignature Credential Request Signature
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async aggregateCredentialSignature (name, credentialKeyPair, credentialSignature) {
    return this.execute([credentialKeyPair, credentialSignature],
      `rule check version 1.0.0
      Scenario coconut: aggregate signature
      Given that I am known as '` + name + `'
      and I have my valid 'credential keypair'
      and I have a valid 'credential signature'
      When I create the credentials
      Then print my 'credentials'
      and print my 'credential keypair'`)
  }

  /**
   * Creates a new Credential Proof.
   *
   * @param {string} name  Holder of the credential.
   * @param {string} nameIssuer Issuer of the credential.
   * @param {object} credential to use
   * @param {object} verifier of credential
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async createCredentialProof (name, nameIssuer, credential, verifier) {
    return this.execute([credential, verifier],
      `rule check version 1.0.0
      Scenario coconut: create proof
      Given that I am known as '` + name + `'
      and I have my valid 'credential keypair'
      and I have a valid 'verifier' from '` + nameIssuer + `'
      and I have my valid 'credentials'
      When I aggregate the verifiers
      and I create the credential proof
      Then print the 'credential proof'`)
  }

  /**
   * Verify a Credential Proof.
   *
   * @param {string} nameIssuer Issuer
   * @param {object} credentialProof to use
   * @param {object} verifier to use
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async verifyCredentialProof (nameIssuer, credentialProof, verifier) {
    return this.execute([credentialProof, verifier],
      `rule check version 1.0.0
      Scenario coconut: verify proof
      Given that I have a valid 'verifier' from '` + nameIssuer + `'
      and I have a valid 'credential proof'
      When I aggregate the verifiers
      and I verify the credential proof
      Then print 'Success' 'OK' as 'string'`)
  }

  /**
   * Create a Random string
   *
   * @param {number} length Length of the random string
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async random (length = 32) {
    return new Promise((resolve) => {
      this.execute(false,
        `rule check version 1.0.0
        Scenario simple: Generate a random password
        Given nothing
        When I create the array of '1' random objects of '256' bits
        Then print the 'array'`).then((rnd) => {
        var b = Buffer.from(rnd.array[0])
        resolve(b.toString('base64').substring(0, length))
      })
    })
  }

  /**
   * Creates a random Pin
   *
   * @param {number} length Length of the random PIN
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async randomPin (length = 6) {
    return new Promise((resolve) => {
      let pin = ''
      this.random(length)
        .then((rnd) => {
          for (let i = 0; i < length; i++) {
            pin += digitalRoot(rnd.charCodeAt(i))
          }
          resolve(pin)
        })
    })
  }

  /**
   * Creates a random DID
   *
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async randomDID () {
    return new Promise((resolve) => {
      this.random(32)
        .then((rnd) => {
          var b = Buffer.from(rnd)
          resolve(b.toString('base64').slice(0, 32))
        })
    })
  }

  /**
   * Create a Hash
   *
   * @param {string} source to be hashed
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async hash (source) {
    return this.execute(false,
      `rule output encoding hex
      Given nothing
      When I write string '` + source + `' in 'source'
      and I create the hash of 'source'
      Then print the 'hash'`)
  }
}
