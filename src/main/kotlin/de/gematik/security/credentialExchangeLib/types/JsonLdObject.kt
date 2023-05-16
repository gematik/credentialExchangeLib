package de.gematik.security.credentialExchangeLib.types

import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UUIDSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

@Serializable
open class JsonLdObject(
    var id: @Serializable(with = UUIDSerializer::class)UUID? = null,
    @SerialName("@context") var atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<@Serializable(with = URISerializer::class) URI>,
    var type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>? = null
){
    abstract class Defaults {
        abstract val DEFAULT_JSONLD_CONTEXTS: List<URI>
        abstract val DEFAULT_JSONLD_TYPES: List<String>
    }
}