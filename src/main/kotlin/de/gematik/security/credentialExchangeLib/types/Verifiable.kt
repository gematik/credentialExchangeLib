package de.gematik.security.credentialExchangeLib.types

import de.gematik.security.credentialExchangeLib.crypto.Signer

interface Verifiable {
    var proof: List<LdProof>?
    fun sign(ldProof: LdProof, signer: Signer)
    fun verify() : Boolean
}