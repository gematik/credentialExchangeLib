package de.gematik.security.credentialExchangeLib.protocols

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
class CredentialRequest : LdObject {
    constructor(
        id: String? = null,
        outputDescriptor: Descriptor,
        holderKey: URI
    ) : super (id, DEFAULT_JSONLD_CONTEXTS, DEFAULT_JSONLD_TYPES){
        this.outputDescriptor = outputDescriptor
        _holderKey = holderKey.toString()
    }

    val outputDescriptor: Descriptor
    @SerialName("holderKey") private val _holderKey : String
    val holderKey
        get() = URI.create(_holderKey)

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://gematik.de/credential-exchange/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "CredentialRequest"
        )
    }
}