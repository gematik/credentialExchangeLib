package de.gematik.security.credentialExchangeLib.protocols

import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
class CredentialOffer : LdObject {
    constructor(
        id: String? = null,
        outputDescriptor: Descriptor,
    ) : super (id, DEFAULT_JSONLD_CONTEXTS, DEFAULT_JSONLD_TYPES){
        this.outputDescriptor = outputDescriptor
    }

    val outputDescriptor: Descriptor

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://gematik.de/credential-exchange/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "CredentialOffer"
        )
    }
}