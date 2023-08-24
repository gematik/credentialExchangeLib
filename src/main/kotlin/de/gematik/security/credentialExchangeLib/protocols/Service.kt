package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import sun.rmi.transport.Endpoint
import java.net.URI


@Serializable
class Service : LdObject {
    constructor(
        id: String? = null,
        atContext: List<URI> = Invitation.DEFAULT_JSONLD_CONTEXTS,
        type: List<String> = Invitation.DEFAULT_JSONLD_TYPES,
        serviceEndpoint: URI,
    ) : super(id, atContext, type) {
        _serviceEndpoint = serviceEndpoint.toString()
    }

    @SerialName("serviceEndpoint") private val _serviceEndpoint: String
    val serviceEndpoint: URI
        get() = URI.create(_serviceEndpoint)

    companion object : LdObject.Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://gematik.de/credential-exchange/v1/")
        )
        override val DEFAULT_JSONLD_TYPES = listOf("BasicService")
    }
}
