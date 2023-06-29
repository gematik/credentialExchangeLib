package de.gematik.security.credentialExchangeLib.crypto

import bbs.signatures.Bbs
import io.github.novacrypto.base58.Base58
import java.net.URI

data class BbsCryptoCredentials(override val keyPair: KeyPair) : CryptoCredentials {
    override val didKey: URI
    override val verKey: String
    override val verificationMethod: URI
    init {
        require(keyPair.publicKey != null)
        require(Bbs.getBls12381G2PublicKeySize() == keyPair.publicKey.size)
        didKey = URI.create("did:key:z${Base58.base58Encode(byteArrayOf(0xeb.toByte(), 0x01) + keyPair.publicKey)}")
        verKey = Base58.base58Encode(keyPair.publicKey)
        verificationMethod = URI.create("${didKey}#${didKey.toString().drop(8)}")
    }
}
