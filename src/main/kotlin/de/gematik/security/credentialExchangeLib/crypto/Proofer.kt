package de.gematik.security.credentialExchangeLib.crypto

import bbs.signatures.ProofMessage

interface Proofer {
    fun deriveProof(signature: ByteArray, nonce: ByteArray, content: List<ProofMessage>): ByteArray
    val derivedProofType : ProofType
}