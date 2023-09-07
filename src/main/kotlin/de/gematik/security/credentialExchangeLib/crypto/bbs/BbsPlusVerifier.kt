package de.gematik.security.credentialExchangeLib.crypto.bbs

import bbs.signatures.Bbs
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.ProofVerifier
import de.gematik.security.credentialExchangeLib.crypto.Verifier
import java.security.GeneralSecurityException

class BbsPlusVerifier(override val publicKey : ByteArray) : Verifier, ProofVerifier {
    init {
        require(publicKey.size == Bbs.getBls12381G2PublicKeySize()) {
            "wrong keysize - expected ${Bbs.getBls12381G2PublicKeySize()} was ${publicKey.size}"
        }
    }

    override fun verify(content : List<ByteArray>, signature: ByteArray) : Boolean {
        return runCatching {
            Bbs.blsVerify(publicKey, signature, content.toTypedArray());
        }.onFailure{throw GeneralSecurityException(it.message) }.getOrThrow()
    }

    override fun verifyProof(content : List<ByteArray>, proof: ByteArray, nonce: ByteArray) : Boolean {
        return runCatching {
            Bbs.blsVerifyProof(publicKey, proof, nonce, content.toTypedArray());
        }.onFailure{throw GeneralSecurityException(it.message) }.getOrThrow()
    }

    override val originalProofType = ProofType.BbsBlsSignature2020
}