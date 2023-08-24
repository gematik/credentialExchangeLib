package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI


@Serializable
class PresentationSubmit : LdObject {
    constructor(
        id: String? = null,
        presentation: Presentation,
    ) : super (id, DEFAULT_JSONLD_CONTEXTS, DEFAULT_JSONLD_TYPES){
        this.presentation = presentation
    }

    val presentation: Presentation

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://gematik.de/credential-exchange/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "PresentationSubmit"
        )
    }
}