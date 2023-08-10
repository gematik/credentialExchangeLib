package de.gematik.security.credentialExchangeLib.crypto

enum class ProofType(val id: String, val isProof: Boolean = false) {
    BbsBlsSignature2020("https://w3id.org/security#BbsBlsSignature2020"),
    BbsBlsSignatureProof2020("https://w3id.org/security#BbsBlsSignatureProof2020", true),
    EcdsaSecp256r1Signature2019("https://w3id.org/security#EcdsaSecp256r1Signature2019"),
    Ed25519Signature2018("https://w3id.org/security#Ed25519Signature2018"),
    EcdsaSecp256k1Signature2019("https://w3id.org/security#EcdsaSecp256k1Signature2019")
}