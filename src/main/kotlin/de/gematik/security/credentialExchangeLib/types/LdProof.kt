package de.gematik.security.credentialExchangeLib.types

import de.gematik.security.credentialExchangeLib.serializer.DateSerializer
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

@Serializable
class LdProof : JsonLdObject{
    constructor(
        id: UUID? = null,
        atContext: List<URI>,
        type: List<String>?,
        creator: URI,
        created: Date,
        domain: String? = null,
        challenge: String? = null,
        nonce: String? = null,
        proofPurpose: ProofPurpose,
        verificationMethod: URI,
        proofValue: String? = null
    ) : super (
        id,
        DEFAULT_JSONLD_CONTEXTS.toMutableList().apply { addAll(atContext) },
        DEFAULT_JSONLD_TYPES.toMutableList().apply { addAll(type?: listOf()) }
    ) {
        this.creator = creator
        this.created = created
        this.domain = domain
        this.challenge = challenge
        this.nonce = nonce
        this.proofPurpose = proofPurpose
        this.verificationMethod = verificationMethod
        this.proofValue = proofValue

    }
    val creator: @Serializable(with = URISerializer::class) URI
    val created: @Serializable(with = DateSerializer::class) Date
    val domain: String?
    val challenge: String?
    var nonce: String?
    val proofPurpose: ProofPurpose
    val verificationMethod: @Serializable(with = URISerializer::class) URI
    var proofValue: String?

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://w3id.org/security/v2")
        )
        override val DEFAULT_JSONLD_TYPES = listOf<String>()
    }
}