package de.gematik.security.credentialExchangeLib.credentialSubjects

import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable

@Serializable
open class JsonLdValue(
    @Required val type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String> = listOf("VaccineEvent")
)