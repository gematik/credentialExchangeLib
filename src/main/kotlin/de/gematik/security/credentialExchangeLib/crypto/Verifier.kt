package de.gematik.security.credentialExchangeLib.crypto

interface Verifier {
    val publicKey: ByteArray
    fun verify(content: List<ByteArray>, signature: ByteArray) : Boolean
}