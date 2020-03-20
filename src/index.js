'use strict'
const zenroom = require('zenroom')

// process.on('uncaughtException', function (err) {
//   console.error((err && err.stack) ? err.stack : err)
// })

// async function silent (asyncFn) {
//   const ogWriteStdout = process.stdout.write.bind(process.stdout)
//   const ogWriteStdErr = process.stderr.write.bind(process.stderr)

//   const log = []
//   const stdoutWrite = (data) => log.push({ stdout: data })
//   const stderrWrite = (data) => log.push({ stderr: data })

//   process.stdout.write = stdoutWrite
//   process.stderr.write = stderrWrite

//   const result = await asyncFn()

//   // reset stdout
//   process.stdout.write = ogWriteStdout
//   process.stderr.write = ogWriteStdErr

//   return result
// }
/**
 * Javascript Class to interact with Zenroom.
 */
module.exports = class Zen {
  /**
   * Executes Zencode.
   *
   * @param {object} keys  Input keys.
   * @param {string} script Zencode to be executed
   * @returns {Promise} Return a promise with the execution of the script.
   */
  execute (keys, script) {
    const options = { verbosity: 0 } // They need to implement verbosity https://github.com/DECODEproject/Zenroom/blob/master/bindings/javascript/src/wrapper.js
    return new Promise((resolve, reject) => {
      zenroom
        .init(options)
        .keys(keys)
        .script(script)
        .print((msg) => {
          console.log(msg)
          resolve(JSON.parse(msg))
        })
        .error((msg) => {
          reject(msg)
        })
        .zencode_exec()
    })
  }

  /**
   * Creates a new keypair.
   *
   * @param {string} name  Holder of the keypair.
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  newKeyPair (name) {
    const zprocess = () => this.execute(false,
      `rule check version 1.0.0
      Scenario simple: Create the keypair
      Given that I am known as '` + name + `'
      When I create the keypair
      Then print my data`
    )
    return zprocess()
  }

  /**
   * Creates a new keypair.
   *
   * @param {string} name  Holder of the keypair.
   * @param {*} keys to create
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  publicKey (name, keys) {
    const zprocess = () => this.execute(keys,
      `rule check version 1.0.0
      Scenario simple Create the keypair
      Given that I am known as '` + name + `'
      and I have my valid 'public key'
      Then print my data`
    )
    return zprocess()
  }

  /**
   * Encrypts a message with a keypair.
   *
   * @param {string} fromName Who's signing the message.
   * @param {object} fromKeys Keypair for the encrypter (Zencode format)
   * @param {string} toName Who's receiving the message.
   * @param {object} toKeys Public Key for the receiver (Zencode format)
   * @param {string} message Message to be encrypted
   * @returns {Promise} Return a promise with the execution of the encryption.
   */
  encryptMessage (fromName, fromKeys, toName, toKeys, message) {
    const zprocess = () => this.execute([fromKeys, toKeys],
      `Rule check version 1.0.0
      Scenario simple: ` + fromName + ' encrypts a message for ' + toName + `
      Given that I am known as '` + fromName + `'
      and I have my valid 'keypair'
      and I have a valid 'public key' from '` + toName + `'
      When I write '` + message + `' in 'message'
      and I write 'This is the header' in 'header'
      and I encrypt the message for '` + toName + `'
      Then print the 'secret_message'`
    )
    return zprocess()
  }

  /**
   * Decrypts a message with a keypair.
   *
   * @param {string} fromName Who's signing the message.
   * @param {object} fromKeys Keypair for the encrypter (Zencode format)
   * @param {string} toName Who's receiving the message.
   * @param {object} toKeys Public Key for the receiver (Zencode format)
   * @param {string} message Message to be decrypted
   * @returns {Promise} Return a promise with the execution of the encryption.
   */
  decryptMessage (fromName, fromKeys, toName, toKeys, message) {
    const zprocess = () => this.execute([fromKeys, toKeys, message],
      `Rule check version 1.0.0
      Scenario simple: ` + toName + ' decrypts the message for ' + fromName + `
      Given that I am known as '` + toName + `'
      and I have my valid 'keypair'
      and I have a valid 'public key' from '` + fromName + `'
      and I have a valid 'secret_message'
      When I decrypt the secret message from '` + fromName + `'
      Then print as 'string' the 'message'
      and print as 'string' the 'header' inside 'secret message'`
    )
    return zprocess()
  }

  /**
   * Signs a message with a keypair.
   *
   * @param {string} signer Who's signing the message.
   * @param {object} keys Keypair for the signer (Zencode format)
   * @param {string} message Message to be signed
   * @returns {Promise} Returns a promise with the execution of the signature.
   */
  signMessage (signer, keys, message) {
    const zprocess = () => this.execute(keys,
      `Rule check version 1.0.0
      Scenario simple: ` + signer + ` signs a message for Recipient
      Given that I am known as '` + signer + `'
      and I have my valid 'keypair'
      When I write '${message}' in 'draft'
      and I create the signature of 'draft'
      Then print my 'signature'
      and print my 'draft'`
    )
    return zprocess()
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
  checkSignature (signer, signerPublic, signature, verifier) {
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
    const zprocess = () => this.execute(keys, checkScript)
    return zprocess()
  }

  /**
   * Creates a new Issuer keypair.
   *
   * @param {string} name  Issuer of the credential keypair.
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  newIssuerKeyPair (name) {
    const zprocess = () => this.execute(false, `rule check version 1.0.0
    Scenario 'coconut': issuer keygen
    Given that I am known as '` + name + `'
    When I create the issuer keypair
    Then print my 'issuer keypair'`)
    return zprocess()
  }

  /**
   * ZKP : Get the Verifier to be published.
   *
   * @param {string} verifier Who's signing the message.
   * @param {object} keys Keypair for the signer (Zencode format)
   * @returns {Promise} Returns a promise with the execution of the signature.
   */
  publishVerifier (verifier, keys) {
    const zprocess = () => this.execute(keys,
      `rule check version 1.0.0
      Scenario 'coconut': publish verifier
      Given that I am known as '` + verifier + `'
      and I have a valid 'verifier'
      Then print my 'verifier'`
    )
    return zprocess()
  }

  /**
   * Creates a new Credential keypair.
   *
   * @param {string} name  Holder of the keypair.
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  newCredentialKeyPair (name) {
    const keygenContract = `rule check version 1.0.0
      Scenario 'coconut': issuer keygen
        Given that I am known as '` + name + `'
        When I create the credential keypair
        Then print my 'credential keypair'`
    const zprocess = () => this.execute(false, keygenContract)
    return zprocess()
  }

  /**
   * Creates a new Signature Request.
   *
   * @param {string} name  Holder of the credential.
   * @param {object} credentialKeyPair Keypair for the credentials (Zencode format)
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  credentialSignatureRequest (name, credentialKeyPair) {
    const zprocess = () => this.execute(credentialKeyPair, `rule check version 1.0.0
      Scenario 'coconut': create request
      Given that I am known as '` + name + `'
      and I have my valid 'credential keypair'
      When I create the credential request
      Then print my 'credential request'`)
    return zprocess()
  }

  /**
   * Creates a new Credential keypair.
   *
   * @param {string} nameIssuer  Issuer of the credential.
   * @param {object} issuerKeyPair Keypair for the Issuer (Zencode format)
   * @param {object} signatureRequest signature Request by the Credential Holder.
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  signCredentialSignatureRequest (nameIssuer, issuerKeyPair, signatureRequest) {
    const zprocess = () => this.execute([issuerKeyPair, signatureRequest],
      `rule check version 1.0.0
      Scenario 'coconut': issuer sign
      Given that I am known as '` + nameIssuer + `'
      and I have my valid 'issuer keypair'
      and I have a valid 'credential request'
      When I create the credential signature
      Then print the 'credential signature'
      and print the 'verifier'`
    )
    return zprocess()
  }

  /**
   * Aggregates signature to the credential Proof.
   *
   * @param {string} name  Holder of the keypair.
   * @param {object} credentialKeyPair Keypair for the credentials (Zencode format)
   * @param {object} credentialSignature Credential Request Signature
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  aggregateCredentialSignature (name, credentialKeyPair, credentialSignature) {
    const zprocess = () => this.execute([credentialKeyPair, credentialSignature],
      `rule check version 1.0.0
      Scenario coconut: aggregate signature
      Given that I am known as '` + name + `'
      and I have my valid 'credential keypair'
      and I have a valid 'credential signature'
      When I create the credentials
      Then print my 'credentials'
      and print my 'credential keypair'`)
    return zprocess()
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
  createCredentialProof (name, nameIssuer, credential, verifier) {
    const zprocess = () => this.execute([credential, verifier],
      `rule check version 1.0.0
      Scenario coconut: create proof
      Given that I am known as '` + name + `'
      and I have my valid 'credential keypair'
      and I have a valid 'verifier' from '` + nameIssuer + `'
      and I have my valid 'credentials'
      When I aggregate the verifiers
      and I create the credential proof
      Then print the 'credential proof'`)
    return zprocess()
  }

  /**
   * Verify a Credential Proof.
   *
   * @param {string} nameIssuer Issuer
   * @param {object} credentialProof to use
   * @param {object} verifier to use
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  verifyCredentialProof (nameIssuer, credentialProof, verifier) {
    const zprocess = () => this.execute([credentialProof, verifier],
      `rule check version 1.0.0
      Scenario coconut: verify proof
      Given that I have a valid 'verifier' from '` + nameIssuer + `'
      and I have a valid 'credential proof'
      When I aggregate the verifiers
      and I verify the credential proof
      Then print 'Success' 'OK' as 'string'`)
    return zprocess()
  }

    /**
   * Create a Hash
   *
   * @param {string} source to be hashed
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async random () {
    return new Promise((resolve) => {
      const zprocess = () => this.execute(false,
        `rule check version 1.0.0
        Scenario simple: Generate a random password
        Given nothing
        When I create the array of '1' random objects of '256' bits
        Then print the 'array'`)
      zprocess().then((rnd) => {
        resolve(rnd.array[0])
      })
      
    })
  }

  /**
   * Create a Hash
   *
   * @param {string} source to be hashed
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  hash (source) {
    const zprocess = () => this.execute(false,
      `rule output encoding hex
      Given nothing
      When I write '` + source + `' in 'source'
      and I create the hash of 'source'
      Then print the 'hash'`)
    return zprocess()
  }
}
