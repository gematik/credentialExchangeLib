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
class Invitation : LdObject {
    constructor(
        id: String? = null,
        atContext: List<URI> = DEFAULT_JSONLD_CONTEXTS,
        type: List<String> = DEFAULT_JSONLD_TYPES,
        label: String,
        goal: String,
        goalCode: GoalCode,
        service: List<Service>
    ) : super(id, atContext, type){
        this.label = label
        this.goal = goal
        this.goalCode = goalCode
        this.service = service
    }
    val label: String
    val goal: String
    val goalCode: GoalCode
    val service: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<Service>

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