package de.gematik.security.credentialExchangeLib.crypto

import bbs.signatures.Bbs
import java.security.GeneralSecurityException

class BbsPlusSigner(override val keyPair: KeyPair) : Signer {
    init {
        require(keyPair.privateKey.size == Bbs.getSecretKeySize()) {
            "wrong private keysize - expected ${Bbs.getSecretKeySize()} was ${keyPair.privateKey.size}"
        }
        require(keyPair.publicKey?.size == Bbs.getBls12381G2PublicKeySize()) {
            "wrong public keysize - expected ${Bbs.getBls12381G2PublicKeySize()} was ${keyPair.publicKey?.size}"
        }
    }

    override fun sign(content : List<ByteArray>) : ByteArray {
        return runCatching {
            Bbs.blsSign(keyPair.privateKey, keyPair.publicKey, content.toTypedArray());
        }.onFailure{throw GeneralSecurityException(it.message)}.getOrThrow()
    }
}