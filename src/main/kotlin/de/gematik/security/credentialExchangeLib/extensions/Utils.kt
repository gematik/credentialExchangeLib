package de.gematik.security.credentialExchangeLib.extensions

import bbs.signatures.Bbs
import de.gematik.security.credentialExchangeLib.crypto.bbs.BbsCryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.ecdsa.P256CryptoCredentials
import io.github.novacrypto.base58.Base58
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.toJavaInstant
import java.math.BigInteger
import java.net.URI
import java.util.*

fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

fun URI.toPublicKey(): ByteArray {
    require(scheme.lowercase() == "did")
    require(schemeSpecificPart.substring(0,3) == "key")
    val byteArray = Base58.base58Decode(fragment.drop(1)).let {it.copyOfRange(2, it.size)}
    return when(schemeSpecificPart.substring(4,7)){
        "zUC" -> if(byteArray.size == Bbs.getBls12381G2PublicKeySize()) byteArray else throw IllegalArgumentException()
        "zDn" -> if(byteArray.size == P256CryptoCredentials.publicKeySize) byteArray else throw IllegalArgumentException()
        else -> throw IllegalArgumentException()
    }
}

class Utils{
    companion object{
        fun getDate(year: Int, month: Int, day: Int) : Date {
            return Date.from(LocalDate(year, month, day).atStartOfDayIn(TimeZone.UTC).toJavaInstant())
        }
    }
}

/**
 * Returns a byteArray of length size containing the unsigned representation of this BigInteger
 * @param size of destination array
 * @return byteArray of length size containing the unsigned representation of this BigInteger
 * @throws [IllegalStateException] if the BigInteger doesn't fit into defined size
 */

fun BigInteger.toByteArray(size: Int): ByteArray {
    val byteList = toByteArray().dropWhile { it == 0.toByte() }
    check(byteList.size <= size){"BigInteger to big"}
    return byteList.toByteArray().copyInto(ByteArray(size),size - byteList.size, 0, size)
}

