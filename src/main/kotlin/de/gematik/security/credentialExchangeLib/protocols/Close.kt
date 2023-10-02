package de.gematik.security.credentialExchangeLib.protocols

import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
class Close : LdObject {
    constructor(
        id: String? = null,
        message: String
    ) : super(id, DEFAULT_JSONLD_CONTEXTS, DEFAULT_JSONLD_TYPES){
        this.message = message
    }
    val message: String
    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://gematik.de/credential-exchange/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "Close"
        )
    }
}