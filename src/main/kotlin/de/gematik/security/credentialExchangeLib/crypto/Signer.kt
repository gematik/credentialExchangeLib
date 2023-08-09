package de.gematik.security.credentialExchangeLib.crypto

interface Signer {
    val keyPair: KeyPair
    fun sign(content: List<ByteArray>) : ByteArray
}