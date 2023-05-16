package de.gematik.security.credentialExchangeLib

import bbs.signatures.Bbs
import io.github.novacrypto.base58.Base58
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import java.net.URI

@OptIn(ExperimentalSerializationApi::class)
val json = Json { prettyPrint = true; explicitNulls=false }

fun URI.verificationMethodtoBls12381G2PublicKey(): ByteArray {
    require(scheme.lowercase() == "did")
    require(schemeSpecificPart.lowercase().startsWith("key:zuc"))
    require(schemeSpecificPart.drop(4) == this.fragment)
    val byteArray = Base58.base58Decode(fragment.drop(1))
    require(byteArray.size == Bbs.getBls12381G2PublicKeySize() + 2)
    require(byteArray.copyOfRange(0, 2).contentEquals(byteArrayOf(0xeb.toByte(), 0x01)))
    return byteArray.copyOfRange(2, byteArray.size)
}
