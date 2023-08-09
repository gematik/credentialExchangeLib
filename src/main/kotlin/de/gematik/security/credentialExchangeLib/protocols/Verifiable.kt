package de.gematik.security.credentialExchangeLib.protocols

interface Verifiable {
    var proof: List<LdProof>?
    fun sign(ldProof: LdProof, privateKey: ByteArray)
    fun verify() : Boolean
}