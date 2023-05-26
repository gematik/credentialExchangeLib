package de.gematik.security.credentialExchangeLib.crypto

interface Signer {
    val keyPair: KeyPair
    fun sign(content: List<ByteArray>) : ByteArray
}

fun getSigner(type: List<String>, keyPair: KeyPair) = when {
    type.firstOrNull { it.endsWith(ProofType.BbsBlsSignature2020.name) } != null -> BbsPlusSigner(keyPair)
    type.firstOrNull { it.endsWith(ProofType.BbsBlsSignatureProof2020.name) } != null -> BbsPlusSigner(keyPair)
    else -> null
}

