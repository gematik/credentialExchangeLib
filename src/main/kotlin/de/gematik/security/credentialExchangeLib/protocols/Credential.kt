package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.extensions.deepCopy
import de.gematik.security.credentialExchangeLib.serializer.DateSerializer
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import okhttp3.internal.toImmutableList
import java.net.URI
import java.security.PrivateKey
import java.util.*

@Serializable
class Credential(
    override val id: String? = null,
    @Required @SerialName("@context") override var atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<@Serializable(with = URISerializer::class) URI> = DEFAULT_JSONLD_CONTEXTS,
    @Required override var type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String> = DEFAULT_JSONLD_TYPES,
    var credentialSubject: JsonObject? = null,
    var issuer: @Serializable(with = URISerializer::class) URI? = null,
    var issuanceDate: @Serializable(with = DateSerializer::class) Date? = null,
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

    override fun sign(ldProof: LdProof, privateKey: ByteArray) {
        val signedProof = ldProof.deepCopy().apply { sign(this@Credential, privateKey)}
        proof = (proof?:emptyList()).toMutableList().apply {
            add(signedProof)
            toImmutableList()
        }
    }

    override fun verify() : Boolean {
        val singleProof = proof?.firstOrNull()
        check(singleProof!=null){"credential doesn't contain a proof for verification"}
        check(proof?.size == 1){"verification of multi signature not supported yet"}
        return singleProof.verify(this)
    }

    fun derive(frame: Credential) : Credential {
        val singleProof = proof?.firstOrNull()
        check(singleProof!=null){"credential doesn't contain a proof for derivation"}
        check(proof?.size == 1){"derive credential with multiple proofs is not supported yet"}
        return singleProof.deriveProof(this, frame)
    }

}

