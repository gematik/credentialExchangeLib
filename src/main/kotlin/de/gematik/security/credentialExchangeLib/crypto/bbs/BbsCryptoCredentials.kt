package de.gematik.security.credentialExchangeLib.crypto.bbs

import bbs.signatures.Bbs
import de.gematik.security.credentialExchangeLib.crypto.CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import io.github.novacrypto.base58.Base58
import java.net.URI
import kotlin.random.Random

data class BbsCryptoCredentials(override val keyPair: KeyPair) : CryptoCredentials {
    companion object{
        val multiCodecId = byteArrayOf(0xeb.toByte(), 0x01)  // varint of 0xeb
        fun createKeyPair() : KeyPair {
            val bbsKeyPair = Bbs.generateBls12381G2Key(Random.nextBytes(32))
            return KeyPair(bbsKeyPair.secretKey, bbsKeyPair.publicKey)
        }
    }
    override val didKey: URI
    override val verKey: String
    override val verificationMethod: URI
    init {
        require(keyPair.publicKey != null)
        require(Bbs.getBls12381G2PublicKeySize() == keyPair.publicKey.size)
        didKey = URI.create("did:key:z${Base58.base58Encode(multiCodecId + keyPair.publicKey)}")
        verKey = Base58.base58Encode(keyPair.publicKey)
        verificationMethod = URI.create("${didKey}#${didKey.toString().drop(8)}")
    }
}
