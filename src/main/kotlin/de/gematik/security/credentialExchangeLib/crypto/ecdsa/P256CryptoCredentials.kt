package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import de.gematik.security.credentialExchangeLib.crypto.CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import io.github.novacrypto.base58.Base58
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import java.math.BigInteger
import java.net.URI

data class P256CryptoCredentials(override val keyPair: KeyPair) : CryptoCredentials {
    companion object {
        val privateKeySize = 32
        val publicKeySize = 33 // compressed key
        val multiCodecId = byteArrayOf(0x80.toByte(), 0x24) // varint of 0x1200
        fun createEcdsaPublicKey(privateKey: ByteArray): ByteArray {
            require(privateKey != null) { "cannot create public key for private key null" }
            var privKey = BigInteger(1, privateKey)
            if (privKey.bitLength() > secp256r1DomainParameters.n.bitLength()) {
                privKey = privKey.mod(secp256r1DomainParameters.n)
            }
            val point = FixedPointCombMultiplier().multiply(secp256r1DomainParameters.g, privKey)
            return point.getEncoded(true)
        }
    }

    override val didKey: URI
    override val verKey: String
    override val verificationMethod: URI

    init {
        require(keyPair.privateKey == null || privateKeySize == keyPair.privateKey.size)
        require(keyPair.publicKey != null && publicKeySize == keyPair.publicKey.size)
        didKey = URI.create("did:key:z${Base58.base58Encode(multiCodecId + keyPair.publicKey)}")
        verKey = Base58.base58Encode(keyPair.publicKey)
        verificationMethod = URI.create("${didKey}#${didKey.toString().drop(8)}")
    }

}
