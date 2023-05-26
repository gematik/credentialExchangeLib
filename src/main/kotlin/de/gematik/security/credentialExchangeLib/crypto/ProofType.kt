package de.gematik.security.credentialExchangeLib.crypto

enum class ProofType(val id: String) {
    BbsBlsSignature2020("https://w3id.org/security#BbsBlsSignature2020"),
    BbsBlsSignatureProof2020("https://w3id.org/security#BbsBlsSignatureProof2020")
}