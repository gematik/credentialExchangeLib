package de.gematik.security.credentialExchangeLib.types

import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.extensions.sign
import de.gematik.security.credentialExchangeLib.extensions.verify
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UUIDSerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import de.gematik.security.mobilewallet.types.Credential
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

@Serializable
class Presentation(
    override val id: String? = null,
    @Required @SerialName("@context") override var atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<@Serializable(with = URISerializer::class) URI> = DEFAULT_JSONLD_CONTEXTS,
    @Required override var type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String> = DEFAULT_JSONLD_TYPES,
    val presentationSubmission: PresentationSubmission,
    val verifiableCredential: List<Credential>,
    override var proof: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<LdProof>? = null
) : LdObject, Verifiable {

    companion object : LdObject.Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://www.w3.org/2018/credentials/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "VerifiablePresentation"
        )
    }

    override fun sign(ldProof: LdProof, signer: Signer){
        ldProof.sign(this, signer)
        proof = listOf(ldProof)
    }

    override fun verify(ldProof: LdProof) : Boolean {
        return ldProof.verify(this)
    }

}

