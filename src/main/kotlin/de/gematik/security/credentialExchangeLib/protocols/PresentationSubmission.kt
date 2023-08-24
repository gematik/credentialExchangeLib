package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UUIDSerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

@Serializable
class PresentationSubmission : LdObject {
    constructor(
        id: String? = null,
        definitionId: UUID,
        descriptorMap: List<DescriptorMapEntry>
    ) : super (id, DEFAULT_JSONLD_CONTEXTS, DEFAULT_JSONLD_TYPES){
        _definitionId = definitionId.toString()
        this.descriptorMap = descriptorMap
    }

    @SerialName("definition_id") private val _definitionId: String
    val definitionId
        get() = UUID.fromString(_definitionId)
    @SerialName("descriptor_map") val descriptorMap: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<DescriptorMapEntry>

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://identity.foundation/presentation-exchange/submission/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "PresentationSubmission"
        )
    }

    @Serializable
    data class DescriptorMapEntry(val id: String, val format: ClaimFormat, val path: String)
}