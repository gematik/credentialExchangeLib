package de.gematik.security.credentialExchangeLib.crypto

import java.security.PrivateKey

interface Verifier {
    val publicKey: ByteArray
    fun verify(content: List<ByteArray>, signature: ByteArray) : Boolean
}

fun getVerifier(type: List<String>, privateKey: ByteArray) = when {
    type.firstOrNull { it.contains(ProofType.BbsBlsSignature2020.name) } != null -> BbsPlusVerifier(privateKey)
    type.firstOrNull { it.contains(ProofType.BbsBlsSignatureProof2020.name) } != null -> BbsPlusVerifier(privateKey)
    else -> null
}
