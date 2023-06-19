package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.crypto.Signer

interface Verifiable {
    var proof: List<LdProof>?
    fun sign(ldProof: LdProof, signer: Signer)
    fun verify() : Boolean
}