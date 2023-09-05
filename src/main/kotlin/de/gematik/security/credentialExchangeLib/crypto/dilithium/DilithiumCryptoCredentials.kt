package de.gematik.security.credentialExchangeLib.crypto.dilithium

import de.gematik.security.credentialExchangeLib.crypto.CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.ecdsa.P256CryptoCredentials
import io.github.novacrypto.base58.Base58
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
import java.math.BigInteger
import java.net.URI
import java.security.PrivateKey
import java.security.SecureRandom

abstract class DilithiumCryptoCredentials(keyPair: KeyPair, privateKeySize: Int, publicKeySize: Int, multiCodecId: ByteArray) : CryptoCredentials {

    companion object {
        fun generateKeyPair(params: DilithiumParameters): KeyPair {
            val dkpg = DilithiumKeyPairGenerator()
            dkpg.init(
                DilithiumKeyGenerationParameters(
                    SecureRandom(),
                    params
                )
            )
            return dkpg.generateKeyPair().let {
                KeyPair(
                    (it.private as DilithiumPrivateKeyParameters).encoded,
                    (it.public as DilithiumPublicKeyParameters).encoded
                )
            }
        }
    }

    final override val keyPair: KeyPair
    final override val didKey: URI
    final override val verKey: String
    final override val verificationMethod: URI

    init {
        require(keyPair.publicKey != null){
            "public key required but missing"
        }
        require(keyPair.publicKey.size == publicKeySize){
            "expected key size is ${publicKeySize} but was ${keyPair.publicKey.size}"
        }
        keyPair.privateKey?.let {
            require(it.size == privateKeySize){
                "expected key size is ${privateKeySize} but was ${keyPair.privateKey.size}"
            }
        }
        this.keyPair = keyPair
        didKey = URI.create("did:key:z${Base58.base58Encode(multiCodecId + keyPair.publicKey)}")
        verKey = Base58.base58Encode(keyPair.publicKey)
        verificationMethod = URI.create("${didKey}#${didKey.toString().drop(8)}")
    }

}

open class Dilithium2CryptoCredentials(keyPair: KeyPair) : DilithiumCryptoCredentials(
    keyPair = keyPair,
    privateKeySize = privateKeySize,
    publicKeySize = publicKeySize,
    multiCodecId = multiCodecId
) {
    companion object {
        val multiCodecId = byteArrayOf(0x87.toByte(), 0x24) // varint of 0x1207
        val privateKeySize = 2528
        val publicKeySize = 1312
        fun generateKeyPair(): KeyPair {
            return DilithiumCryptoCredentials.generateKeyPair(DilithiumParameters.dilithium2)
        }
    }
}

class Dilithium2AesCryptoCredentials(keyPair: KeyPair) : Dilithium2CryptoCredentials(keyPair) {
    companion object {
        fun generateKeyPair(): KeyPair {
            return DilithiumCryptoCredentials.generateKeyPair(DilithiumParameters.dilithium2_aes)
        }
    }
}

open class Dilithium3CryptoCredentials(keyPair: KeyPair) : DilithiumCryptoCredentials(
    keyPair = keyPair,
    privateKeySize = privateKeySize,
    publicKeySize = publicKeySize,
    multiCodecId = multiCodecId
) {
    companion object {
        val multiCodecId = byteArrayOf(0x88.toByte(), 0x24) // varint of 0x1208
        val privateKeySize = 4000
        val publicKeySize = 1952
        fun generateKeyPair(): KeyPair {
            return DilithiumCryptoCredentials.generateKeyPair(DilithiumParameters.dilithium3)
        }
    }
}

class Dilithium3AesCryptoCredentials(keyPair: KeyPair) : Dilithium3CryptoCredentials(keyPair) {
    companion object {
        fun generateKeyPair(): KeyPair {
            return DilithiumCryptoCredentials.generateKeyPair(DilithiumParameters.dilithium3_aes)
        }
    }
}

open class Dilithium5CryptoCredentials(keyPair: KeyPair) : DilithiumCryptoCredentials(
    keyPair = keyPair,
    privateKeySize = privateKeySize,
    publicKeySize = publicKeySize,
    multiCodecId = multiCodecId
) {
    companion object {
        val multiCodecId = byteArrayOf(0x89.toByte(), 0x24) // varint of 0x1209
        val privateKeySize = 4864
        val publicKeySize = 2592
        fun generateKeyPair(): KeyPair {
            return DilithiumCryptoCredentials.generateKeyPair(DilithiumParameters.dilithium5)
        }
    }
}

class Dilithium5AesCryptoCredentials(keyPair: KeyPair) : Dilithium5CryptoCredentials(keyPair) {
    companion object {
        fun generateKeyPair(): KeyPair {
            return DilithiumCryptoCredentials.generateKeyPair(DilithiumParameters.dilithium5_aes)
        }
    }
}