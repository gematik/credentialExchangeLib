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
class PresentationSubmission(
    override val id: String? = null,
    @Required @SerialName("@context") override var atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<@Serializable(with = URISerializer::class) URI> = DEFAULT_JSONLD_CONTEXTS,
    @Required override var type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String> = DEFAULT_JSONLD_TYPES,
    @SerialName("definition_id") val definitionId: @Serializable(with = UUIDSerializer::class) UUID,
    @SerialName("descriptor_map") val descriptorMap: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<DescriptorMapEntry>
) : LdObject {

    companion object : LdObject.Defaults() {
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