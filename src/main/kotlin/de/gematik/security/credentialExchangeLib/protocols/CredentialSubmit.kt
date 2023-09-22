package de.gematik.security.credentialExchangeLib.protocols

import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
class CredentialSubmit : LdObject {
    constructor(
        id: String? = null,
        credential: Credential
    ) : super (id, DEFAULT_JSONLD_CONTEXTS, DEFAULT_JSONLD_TYPES){
        this.credential = credential
    }

    val credential: Credential

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://gematik.de/credential-exchange/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "CredentialSubmit"
        )
    }
}