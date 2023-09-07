package de.gematik.security.credentialExchangeLib.crypto.dilithium

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
import java.security.MessageDigest

fun DilithiumParameters.getPrivateKeyParameters(encoded: ByteArray): DilithiumPrivateKeyParameters {

    data class Sizes(
        val rho: Int = 32,
        val k: Int = 32,
        val tr: Int = 32,
        val s1: Int,
        val s2: Int,
        val t0: Int
    )

    val sizes = when (this) {
        DilithiumParameters.dilithium2, DilithiumParameters.dilithium2_aes -> {
            require(encoded.size == 2528) {
                "expected key size is 2528, but was ${encoded.size}"
            }
            Sizes(s1 = 384, s2 = 384, t0 = 1664)
        }

        DilithiumParameters.dilithium3, DilithiumParameters.dilithium3_aes -> {
            require(encoded.size == 4000) {
                "expected key size is 4000, but was ${encoded.size}"
            }
            Sizes(s1 = 640, s2 = 768, t0 = 2496)
        }

        DilithiumParameters.dilithium5, DilithiumParameters.dilithium5_aes -> {
            require(encoded.size == 4864) {
                "expected key size is 4864, but was ${encoded.size}"
            }
            Sizes(s1 = 672, s2 = 768, t0 = 3328)
        }

        else -> throw NotImplementedError("DilithiumParameters ${this.name} not implemented")
    }
    var startIndex = 0
    return DilithiumPrivateKeyParameters(
        this,
        encoded.copyOfRange(startIndex, startIndex.let { startIndex = it + sizes.rho; startIndex }),
        encoded.copyOfRange(startIndex, startIndex.let { startIndex = it + sizes.k; startIndex }),
        encoded.copyOfRange(startIndex, startIndex.let { startIndex = it + sizes.tr; startIndex }),
        encoded.copyOfRange(startIndex, startIndex.let { startIndex = it + sizes.s1; startIndex }),
        encoded.copyOfRange(startIndex, startIndex.let { startIndex = it + sizes.s2; startIndex }),
        encoded.copyOfRange(startIndex, startIndex.let { startIndex = it + sizes.t0; startIndex }),
        null
    )
}

fun DilithiumParameters.getPublicKeyParameters(encoded: ByteArray): DilithiumPublicKeyParameters {

    data class Sizes(
        val rho: Int = 32,
        val t1: Int
    )

    val sizes = when (this) {
        DilithiumParameters.dilithium2, DilithiumParameters.dilithium2_aes -> {
            require(encoded.size == 1312) {
                "expected key size is 1312, but was ${encoded.size}"
            }
            Sizes(t1 = 1280)
        }

        DilithiumParameters.dilithium3, DilithiumParameters.dilithium3_aes -> {
            require(encoded.size == 1952) {
                "expected key size is 1952, but was ${encoded.size}"
            }
            Sizes(t1 = 1920)
        }

        DilithiumParameters.dilithium5, DilithiumParameters.dilithium5_aes -> {
            require(encoded.size == 2592) {
                "expected key size is 4864, but was ${encoded.size}"
            }
            Sizes(t1 = 2560)
        }

        else -> throw NotImplementedError("DilithiumParameters ${this.name} not implemented")
    }
    var startIndex = 0
    return DilithiumPublicKeyParameters(
        this,
        encoded.copyOfRange(startIndex, startIndex.let { startIndex = it + sizes.rho; startIndex }),
        encoded.copyOfRange(startIndex, startIndex.let { startIndex = it + sizes.t1; startIndex })
    )
}

fun List<ByteArray>.getSaltedHashes(salt: ByteArray) : List<ByteArray>{
    val saltedHashes = emptyList<ByteArray>().toMutableList()
    var s = salt
    forEach {
        val saltedHash = MessageDigest.getInstance("SHA-256").apply {
            update(s)
            update(it)
        }.digest()
        saltedHashes.add(saltedHash)
        s = saltedHash
    }
    return saltedHashes
}
