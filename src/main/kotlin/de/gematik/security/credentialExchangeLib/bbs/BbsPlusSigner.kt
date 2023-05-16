package de.gematik.security.credentialExchangeLib.bbs

import bbs.signatures.Bbs
import bbs.signatures.KeyPair
import java.security.GeneralSecurityException

class BbsPlusSigner(val keyPair: KeyPair) {
    init {
        require(keyPair.secretKey.size == Bbs.getSecretKeySize()) {
            "wrong keysize - expected ${Bbs.getSecretKeySize()} was ${keyPair.secretKey.size}"
        }
    }

    fun sign(content : List<ByteArray>) : ByteArray {
        return runCatching {
            Bbs.blsSign(keyPair.secretKey, keyPair.publicKey, content.toTypedArray());
        }.onFailure{throw GeneralSecurityException(it.message)}.getOrThrow()
    }
}