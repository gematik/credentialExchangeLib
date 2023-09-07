package de.gematik.security.credentialExchangeLib.crypto

interface ProofVerifier {
    fun verifyProof(content : List<ByteArray>, proof: ByteArray, nonce: ByteArray) : Boolean
    val originalProofType: ProofType
}