package de.gematik.security.credentialExchangeLib.crypto

interface AsyncSigner {
    suspend fun asyncSign(content: List<ByteArray>, context: Any) : ByteArray
}