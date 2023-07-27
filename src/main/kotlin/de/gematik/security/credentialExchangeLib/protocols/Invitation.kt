package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import java.net.URI
import java.util.*

@Serializable
class Invitation(
    override val id: String,
    @Required @SerialName("@context") override val atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<@Serializable(
        with = URISerializer::class
    ) URI> = DEFAULT_JSONLD_CONTEXTS,
    @Required override var type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>? = DEFAULT_JSONLD_TYPES,
    val label: String,
    val goal: String,
    val goalCode: GoalCode,
    val service: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<Service>,
) : LdObject {
    companion object : LdObject.Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://gematik.de/credential-exchange/v1/")
        )
        override val DEFAULT_JSONLD_TYPES = listOf("Invitation")

        fun fromBase64(string: String) : Invitation {
            return json.decodeFromString<Invitation>(String(Base64.getDecoder().decode(string)))
        }
    }

    fun toBase64() : String {
        return Base64.getEncoder().encodeToString(json.encodeToString(this).toByteArray())
    }

}

enum class GoalCode{
    OFFER_CREDENDIAL,
    REQUEST_CREDENTIAL,
    REQUEST_PRESENTATION,
    OFFER_PRESENTATION
}