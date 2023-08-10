package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import de.gematik.security.credentialExchangeLib.crypto.CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import io.github.novacrypto.base58.Base58
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import java.math.BigInteger

abstract class EcdsaCryptoCredentials(keyPair: KeyPair) : CryptoCredentials {

    companion object {
        val privateKeySize = 32
        val publicKeySize = 33 // compressed key - prefix 02 if y is even or 03 if y is odd
        val publicKeySizeUncompressed = 65 // uncompressed key - prefix 04 (04|XX.. 32 byte x ..XX|XX.. 32 byte y ..XX)
        fun createPublicKey(privateKey: ByteArray, ecDomainParameters : ECDomainParameters): ByteArray {
            var privKey = BigInteger(1, privateKey)
            if (privKey.bitLength() > ecDomainParameters.n.bitLength()) {
                privKey = privKey.mod(ecDomainParameters.n)
            }
            val point = FixedPointCombMultiplier().multiply(ecDomainParameters.g, privKey)
            return point.getEncoded(true)
        }
        fun decompressPublicKey(compressedPublicKey: ByteArray, ecDomainParameters : ECDomainParameters) : ByteArray {
            require(compressedPublicKey.size == 33)
            require(compressedPublicKey[0] == 2.toByte() || compressedPublicKey[0] == 3.toByte() )
            return ecDomainParameters.curve.decodePoint(compressedPublicKey).getEncoded(false)
        }
    }

    final override val keyPair: KeyPair
    final override val verKey: String

    init {
        require(keyPair.publicKey != null && publicKeySize == keyPair.publicKey.size)
        this.keyPair = keyPair
        verKey = Base58.base58Encode(keyPair.publicKey)
    }

}