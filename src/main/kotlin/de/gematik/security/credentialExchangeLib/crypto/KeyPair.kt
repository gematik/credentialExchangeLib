package de.gematik.security.credentialExchangeLib.crypto

data class KeyPair(val privateKey: ByteArray, val publicKey: ByteArray? = null)
