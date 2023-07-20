package de.gematik.security.credentialExchangeLib.extensions

import bbs.signatures.Bbs
import io.github.novacrypto.base58.Base58
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.toJavaInstant
import java.net.URI
import java.util.*

fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

fun URI.toBls12381G2PublicKey(): ByteArray {
    require(scheme.lowercase() == "did")
    require(schemeSpecificPart.lowercase().startsWith("key:zuc"))
    require(schemeSpecificPart.drop(4) == this.fragment)
    val byteArray = Base58.base58Decode(fragment.drop(1))
    require(byteArray.size == Bbs.getBls12381G2PublicKeySize() + 2)
    require(byteArray.copyOfRange(0, 2).contentEquals(byteArrayOf(0xeb.toByte(), 0x01)))
    return byteArray.copyOfRange(2, byteArray.size)
}

class Utils{
    companion object{
        fun getDate(year: Int, month: Int, day: Int) : Date {
            return Date.from(LocalDate(year, month, day).atStartOfDayIn(TimeZone.UTC).toJavaInstant())
        }
    }
}
