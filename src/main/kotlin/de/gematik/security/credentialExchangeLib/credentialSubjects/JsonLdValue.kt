package de.gematik.security.credentialExchangeLib.credentialSubjects

import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
open class JsonLdValue(
    @Required val type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>,
    var id: @Serializable(with = URISerializer::class) URI? = null
    )