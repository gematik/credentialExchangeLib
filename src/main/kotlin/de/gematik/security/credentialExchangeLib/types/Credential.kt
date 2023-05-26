package de.gematik.security.mobilewallet.types

import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.serializer.DateSerializer
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import de.gematik.security.credentialExchangeLib.types.LdObject
import de.gematik.security.credentialExchangeLib.types.LdProof
import de.gematik.security.credentialExchangeLib.types.Verifiable
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.util.*

@Serializable
class Credential(
    override val id: String? = null,
    @Required @SerialName("@context") override var atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<@Serializable(with = URISerializer::class) URI> = DEFAULT_JSONLD_CONTEXTS,
    @Required override var type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String> = DEFAULT_JSONLD_TYPES,
    val credentialSubject: JsonObject? = null,
    val issuer: @Serializable(with = URISerializer::class) URI? = null,
    val issuanceDate: @Serializable(with = DateSerializer::class) Date? = null,
    override var proof: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<LdProof>? = null
) : LdObject, Verifiable {

    companion object : LdObject.Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://www.w3.org/2018/credentials/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "VerifiableCredential"
        )
    }

    override fun sign(ldProof: LdProof, signer: Signer){
        ldProof.sign(this, signer)
        proof = (proof?: emptyList()) + listOf(ldProof)
    }

    override fun verify() : Boolean {
        val pr = proof?.get(0)
        check(pr!=null){"credential doesn't contain a proof for verification"}
        check(proof?.size == 1){"verfication of multi signature not supported yet"}
        return pr.verify(this)
    }

    fun derive(frame: Credential) : Credential {
        val pr = proof?.get(0)
        check(pr!=null){"credential doesn't contain a proof for derivation"}
        check(proof?.size == 1){"derive credential with multiple proofs is not supported yet"}
        return pr.deriveProof(this, frame)
    }
}

