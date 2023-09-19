package de.gematik.security.credentialExchangeLib.extensions

import bbs.signatures.Bbs
import de.gematik.security.credentialExchangeLib.crypto.dilithium.Dilithium2CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.dilithium.Dilithium3CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.dilithium.Dilithium5CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.ecdsa.EcdsaCryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.ecdsa.Ed25519CryptoCredentials
import io.github.novacrypto.base58.Base58
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.toJavaInstant
import java.math.BigInteger
import java.net.URI
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*

fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

fun ByteArray.toHex(discardLeadingZeros: Boolean = false): String {
    val string = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
    return "0x${if (discardLeadingZeros) string.trimStart('0') else string}"
}

fun URI.toPublicKey(): ByteArray {
    require(scheme.lowercase() == "did")
    require(schemeSpecificPart.substring(0, 3) == "key")
    val byteArray = Base58.base58Decode(fragment.drop(1)).let { it.copyOfRange(2, it.size) }
    return when (schemeSpecificPart.substring(4, 7)) {
        "zUC" -> if (byteArray.size == Bbs.getBls12381G2PublicKeySize()) byteArray else throw IllegalArgumentException("zUC : wrong key size")
        "zDn" -> if (byteArray.size == EcdsaCryptoCredentials.publicKeySize) byteArray else throw IllegalArgumentException(
            "zDn : wrong key size"
        )

        "z6M" -> if (byteArray.size == Ed25519CryptoCredentials.publicKeySize) byteArray else throw IllegalArgumentException(
            "z6M : wrong key size"
        )

        "zQ3" -> if (byteArray.size == EcdsaCryptoCredentials.publicKeySize) byteArray else throw IllegalArgumentException(
            "zQ3 : wrong key size"
        )

        "z4d" -> if (byteArray.size == Dilithium2CryptoCredentials.publicKeySize) byteArray else throw IllegalArgumentException(
            "zX9 : wrong key size"
        )

        "z4z" -> if (byteArray.size == Dilithium3CryptoCredentials.publicKeySize) byteArray else throw IllegalArgumentException(
            "z4z : wrong key size"
        )

        "z5P" -> if (byteArray.size == Dilithium5CryptoCredentials.publicKeySize) byteArray else throw IllegalArgumentException(
            "z5P : wrong key size"
        )

        else -> throw IllegalArgumentException("unsupported multiformat prefix: ${schemeSpecificPart.substring(4, 7)}")
    }
}

fun createUri(host: String, port: Int, path: String? = null, query: String? = null): URI {
    return URI(null, null, host, port, path, query, null)
}

fun String.params(): List<Pair<String, String>> {
    return split('&').map {
        it.split('=').let { Pair(it[0], it[1]) }
    }
}

fun String.params(key: String): String {
    return split('&').map {
        it.split('=').let { Pair(it[0], it[1]) }
    }.first { it.first.lowercase() == key.lowercase() }.second
}

/**
 * Returns a byteArray of length size containing the unsigned representation of this BigInteger
 * @param size of destination array
 * @return byteArray of length size containing the unsigned representation of this BigInteger
 * @throws [IllegalStateException] if the BigInteger doesn't fit into defined size
 */

fun BigInteger.toByteArray(size: Int): ByteArray {
    val byteList = toByteArray().dropWhile { it == 0.toByte() }
    check(byteList.size <= size) { "BigInteger to big" }
    return byteList.toByteArray().copyInto(ByteArray(size), size - byteList.size, 0, size)
}

fun ZonedDateTime.toIsoInstantString(): String {
    return withNano(0).format(DateTimeFormatter.ISO_INSTANT)
}

fun String.toZonedDateTime(): ZonedDateTime {
    return ZonedDateTime.parse(this)
}

fun getZonedTime(year: Int, month: Int, day: Int, hour: Int, minute: Int): ZonedDateTime {
    return ZonedDateTime.of(year, month, day, hour, minute, 0, 0, ZoneId.of("UTC"))
}

fun getZonedDate(year: Int, month: Int, day: Int): ZonedDateTime {
    return ZonedDateTime.of(year, month, day, 12, 0, 0, 0, ZoneId.of("UTC"))
}
