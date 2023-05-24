package de.gematik.security.credentialExchangeLib.types

import de.gematik.security.credentialExchangeLib.serializer.DateSerializer
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UUIDSerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import de.gematik.security.mobilewallet.types.Credential
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import okhttp3.internal.toImmutableList
import java.net.URI
import java.util.*

@Serializable
class LdProof(
    override val id: String? = null,
    @Required @SerialName("@context") override val atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<@Serializable(with = URISerializer::class) URI> = DEFAULT_JSONLD_CONTEXTS,
    @Required override val type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>? = DEFAULT_JSONLD_TYPES,
    val creator: @Serializable(with = URISerializer::class) URI,
    val created: @Serializable(with = DateSerializer::class) Date,
    val domain: String? = null,
    val challenge: String? = null,
    val nonce: String? = null,
    val proofPurpose: ProofPurpose,
    val verificationMethod: @Serializable(with = URISerializer::class) URI,
    var proofValue: String? = null
) : LdObject {

    companion object : LdObject.Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://w3id.org/security/v2")
        )
        override val DEFAULT_JSONLD_TYPES = listOf<String>()
    }

}