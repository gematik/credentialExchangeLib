package de.gematik.security.mobilewallet.types

import de.gematik.security.credentialExchangeLib.extensions.sign
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import de.gematik.security.credentialExchangeLib.bbs.BbsPlusSigner
import de.gematik.security.credentialExchangeLib.types.JsonLdObject
import de.gematik.security.credentialExchangeLib.types.LdProof
import de.gematik.security.credentialExchangeLib.types.Proofable
import de.gematik.security.credentialExchangeLib.serializer.DateSerializer
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.util.*

@Serializable
class Credential : JsonLdObject, Proofable {
    constructor(
        id: UUID? = null,
        atContext: List<URI>,
        type: List<String>?,
        credentialSubject: JsonObject,
        issuer: URI,
        issuanceDate: Date,
        proof: List<LdProof>? = null
    ) : super(
        id,
        DEFAULT_JSONLD_CONTEXTS.toMutableList().apply { addAll(atContext) },
        DEFAULT_JSONLD_TYPES.toMutableList().apply { addAll(type?: listOf()) }
    ) {
        this.credentialSubject = credentialSubject
        this.issuer = issuer
        this.issuanceDate = issuanceDate
        this.proof = proof
    }

    val credentialSubject: JsonObject
    val issuer: @Serializable(with = URISerializer::class) URI
    val issuanceDate: @Serializable(with = DateSerializer::class) Date
    override var proof: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<LdProof>?

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://www.w3.org/2018/credentials/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "VerifiableCredential"
        )
    }

    fun sign(ldProof: LdProof, signer: BbsPlusSigner){
        ldProof.sign(this, signer)
        proof = listOf(ldProof)
    }
}

