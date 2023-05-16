package de.gematik.security.credentialExchangeLib.bbs

import bbs.signatures.Bbs
import java.security.GeneralSecurityException

class BbsPlusVerifier(val publicKey : ByteArray) {
    init {
        require(publicKey.size == Bbs.getBls12381G2PublicKeySize()) {
            "wrong keysize - expected ${Bbs.getBls12381G2PublicKeySize()} was ${publicKey.size}"
        }
    }

    fun verify(content : List<ByteArray>, signature: ByteArray) : Boolean {
        return runCatching {
            Bbs.blsVerify(publicKey, signature, content.toTypedArray());
        }.onFailure{throw GeneralSecurityException(it.message) }.getOrThrow()
    }
}