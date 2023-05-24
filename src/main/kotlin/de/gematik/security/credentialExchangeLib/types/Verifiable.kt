package de.gematik.security.credentialExchangeLib.types

import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.crypto.Verifier

interface Verifiable {
    var proof: List<LdProof>?
    fun sign(ldProof: LdProof, signer: Signer)
    fun verify(ldProof: LdProof) : Boolean
}