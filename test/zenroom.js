const Zen = require('../src/index')
const chai = require('chai')
  .use(require('chai-as-promised'))
const assert = chai.assert

const message = 'Hello_World'
let aliceKeypair; let alicePublic; let signature = false
let bobKeypair; let bobPublic; let msgEncrypted = false
const z = new Zen()

describe('Zenroom', function () {
  // Keypairs.
  describe('KeyPair generation: ', () => {
    it('Should create a new KeyPair: ', async () => {
      aliceKeypair = await z.newKeyPair('Alice')
      assert.isNotEmpty(aliceKeypair.Alice.keypair)
      assert.isNotEmpty(aliceKeypair.Alice.keypair.public_key)
      assert.isNotEmpty(aliceKeypair.Alice.keypair.private_key)

      bobKeypair = await z.newKeyPair('Bob')
      assert.isNotEmpty(bobKeypair.Bob.keypair)
      assert.isNotEmpty(bobKeypair.Bob.keypair.public_key)
      assert.isNotEmpty(bobKeypair.Bob.keypair.private_key)
    })

    it('Should get the Public Key', async () => {
      alicePublic = await z.publicKey('Alice', aliceKeypair)
      assert.isNotEmpty(alicePublic.Alice.public_key)
      assert.strictEqual(alicePublic.Alice.private_key, undefined)
      bobPublic = await z.publicKey('Bob', bobKeypair)
      assert.isNotEmpty(bobPublic.Bob.public_key)
      assert.strictEqual(bobPublic.Bob.private_key, undefined)
    })
  })

  // Encryption.
  describe('Encryption: ', () => {
    it('Should encrypt a message: ', async () => {
      msgEncrypted = await z.encryptMessage('Alice', aliceKeypair, 'Bob', bobPublic, message)
      assert.isNotEmpty(msgEncrypted.secret_message)
      assert.isNotEmpty(msgEncrypted.secret_message.iv)
      assert.isNotEmpty(msgEncrypted.secret_message.header)
      assert.isNotEmpty(msgEncrypted.secret_message.text)
      assert.isNotEmpty(msgEncrypted.secret_message.checksum)
    })

    it('Should decrypt a message: ', async () => {
      const msg = await z.decryptMessage('Alice', alicePublic, 'Bob', bobKeypair, msgEncrypted)
      assert.equal(msg.message, message)
    })
  })

  // Signatures.
  describe('Signatures: ', () => {
    it('Should create a new Signature: ', async () => {
      signature = await z.signMessage('Alice', aliceKeypair, message)
      assert.isNotEmpty(signature.Alice)
      assert.isNotEmpty(signature.Alice.signature)
      assert.isNotEmpty(signature.Alice.signature.r)
      assert.isNotEmpty(signature.Alice.signature.s)
    })

    it('Should Check the Signature: ', async () => {
      const check = await z.checkSignature('Alice', alicePublic, signature, 'Bob')
      assert.equal(check.signature, 'correct')
    })
  })

  // Zero Knowledge Proof
  describe('ZKP: ', () => {
    let issuerKeyPair, verifier, credentialKeyPair, credentialRequest
    let signedSignature, credential, credentialProof

    it('1. Should create an Issuer KeyPair: ', async () => {
      issuerKeyPair = await z.newIssuerKeyPair('Issuer')
      assert.isNotEmpty(issuerKeyPair.Issuer.issuer_keypair)
      assert.isNotEmpty(issuerKeyPair.Issuer.issuer_keypair)
      assert.isNotEmpty(issuerKeyPair.Issuer.issuer_keypair.issuer_sign)
      assert.isNotEmpty(issuerKeyPair.Issuer.issuer_keypair.issuer_sign.x)
      assert.isNotEmpty(issuerKeyPair.Issuer.issuer_keypair.issuer_sign.y)
      assert.isNotEmpty(issuerKeyPair.Issuer.issuer_keypair.verifier)
      assert.isNotEmpty(issuerKeyPair.Issuer.issuer_keypair.verifier.alpha)
      assert.isNotEmpty(issuerKeyPair.Issuer.issuer_keypair.verifier.beta)
    })

    it('2. Should create a Verifier (published): ', async () => {
      verifier = await z.publishVerifier('Issuer', issuerKeyPair.Issuer)
      assert.isNotEmpty(verifier.Issuer)
      assert.isNotEmpty(verifier.Issuer.verifier)
      assert.isNotEmpty(verifier.Issuer.verifier.alpha)
      assert.isNotEmpty(verifier.Issuer.verifier.beta)
    })

    it('3. Should create a Credential KeyPair: ', async () => {
      credentialKeyPair = await z.newCredentialKeyPair('Alice')
      assert.isNotEmpty(credentialKeyPair.Alice)
      assert.isNotEmpty(credentialKeyPair.Alice.credential_keypair)
      assert.isNotEmpty(credentialKeyPair.Alice.credential_keypair.public)
      assert.isNotEmpty(credentialKeyPair.Alice.credential_keypair.private)
    })

    it('4. Should create a credential Signature Request: ', async () => {
      credentialRequest = await z.credentialSignatureRequest('Alice', credentialKeyPair)
      assert.isNotEmpty(credentialRequest.Alice)
      assert.isNotEmpty(credentialRequest.Alice.credential_request)
      assert.isNotEmpty(credentialRequest.Alice.credential_request.public)
      assert.isNotEmpty(credentialRequest.Alice.credential_request.pi_s)
      assert.isNotEmpty(credentialRequest.Alice.credential_request.c)
      assert.isNotEmpty(credentialRequest.Alice.credential_request.commit)
    })

    it('5. Should sign a credential Request: ', async () => {
      signedSignature = await z.signCredentialSignatureRequest('Issuer', issuerKeyPair, credentialRequest.Alice)
      assert.isNotEmpty(signedSignature)
      assert.isNotEmpty(signedSignature.credential_signature)
      assert.isNotEmpty(signedSignature.credential_signature.a_tilde)
      assert.isNotEmpty(signedSignature.credential_signature.b_tilde)
      assert.isNotEmpty(signedSignature.credential_signature.h)
      assert.isNotEmpty(signedSignature.verifier)
      assert.isNotEmpty(signedSignature.verifier.alpha)
      assert.isNotEmpty(signedSignature.verifier.beta)
    })

    it('6. Should aggregate the credential signature: ', async () => {
      credential = await z.aggregateCredentialSignature('Alice', credentialKeyPair, signedSignature)
      assert.isNotEmpty(credential)
      assert.isNotEmpty(credential.Alice)
      assert.isNotEmpty(credential.Alice.credentials)
      assert.isNotEmpty(credential.Alice.credentials.s)
      assert.isNotEmpty(credential.Alice.credentials.h)
      assert.isNotEmpty(credential.Alice.credential_keypair)
      assert.isNotEmpty(credential.Alice.credential_keypair.public)
      assert.isNotEmpty(credential.Alice.credential_keypair.private)
    })

    it('7. Should create a Credential Proof: ', async () => {
      credentialProof = await z.createCredentialProof('Alice', 'Issuer', credential, verifier)
      assert.isNotEmpty(credentialProof)
      assert.isNotEmpty(credentialProof.credential_proof)
      assert.isNotEmpty(credentialProof.credential_proof.kappa)
      assert.isNotEmpty(credentialProof.credential_proof.pi_v)
      assert.isNotEmpty(credentialProof.credential_proof.pi_v.rr)
      assert.isNotEmpty(credentialProof.credential_proof.pi_v.rm)
      assert.isNotEmpty(credentialProof.credential_proof.pi_v.c)
      assert.isNotEmpty(credentialProof.credential_proof.nu)
      assert.isNotEmpty(credentialProof.credential_proof.sigma_prime)
      assert.isNotEmpty(credentialProof.credential_proof.sigma_prime.h_prime)
      assert.isNotEmpty(credentialProof.credential_proof.sigma_prime.s_prime)
    })

    it('8. Should verify a Credential Proof: ', async () => {
      const verifyCredential = await z.verifyCredentialProof('Issuer', credentialProof, verifier)
      assert.equal(verifyCredential.Success, 'OK')
    })
  })

  // Zero Knowledge Proof
  describe('Hash: ', () => {
    it('9. Should hash a String: ', async () => {
      const result = await z.hash('Hello world')
      assert.isNotEmpty(result.hash)
    })
  })

  describe('Random: ', () => {
    it('10. Should create a random Number: ', async () => {
      const rnd = await z.random()
      assert.isNotEmpty(rnd)
    })
  })
})
