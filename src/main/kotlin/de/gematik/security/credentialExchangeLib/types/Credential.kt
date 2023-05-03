package de.gematik.security.mobilewallet.types

import de.gematik.security.mobilewallet.extensions.toDate
import de.gematik.security.mobilewallet.extensions.toJsonLdString
import de.gematik.security.mobilewallet.serializer.CredentialSerializer
import foundation.identity.jsonld.JsonLDObject
import foundation.identity.jsonld.JsonLDUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import java.net.URI
import java.util.*
import kotlin.reflect.jvm.internal.impl.load.kotlin.JvmType

@Serializable(with = CredentialSerializer::class)
class Credential(json: Map<String, Any>) : JsonLDObject(json) {

    lateinit var credentialSubject: Map<String, Any>
        private set
    lateinit var issuer: URI
        private set
    lateinit var issuanceDate: Date
        private set
    var proof: Map<String, Any>? = null
        private set

    companion object {
        @JvmField
        val DEFAULT_JSONLD_CONTEXTS: Array<URI> = arrayOf(
            URI("https://www.w3.org/2018/credentials/v1")
        )

        @JvmField
        val DEFAULT_JSONLD_TYPES: Array<String> = arrayOf(
            "VerifiableCredential"
        )

        fun fromJson(json: String): Credential? {
            return Credential(readJson(json)).apply {
                //TODO: check context and type
                runCatching {
                    @Suppress("UNCHECKED_CAST")
                    credentialSubject = (jsonObject["credentialSubject"] as Map<String, Any>)
                    issuer = URI.create(jsonObject["issuer"] as String)
                    issuanceDate = (jsonObject["issuanceDate"] as String).toDate()
                    @Suppress("UNCHECKED_CAST")
                    proof = jsonObject["proof"] as? Map<String, Any>
                }.onFailure { throw SerializationException(it.message) }
            }
        }
    }

    constructor(
        id: URI? = null,
        context: List<URI>,
        type: List<String>,
        credentialSubject: Map<String, Any>,
        issuer: URI,
        issuanceDate: Date,
        proof: Map<String, Any>? = null
    ) : this(mutableMapOf<String, Any>()) {
        // id
        id?.let { JsonLDUtils.jsonLdAdd(this, "id", id.toString()) }
        // contexts
        JsonLDUtils.jsonLdAddAsJsonArray(
            this,
            "context",
            mutableListOf<String>().apply {
                addAll(DEFAULT_JSONLD_CONTEXTS.map { it.toString() })
                addAll(context.map { it.toString() })
            }
        )
        // types
        JsonLDUtils.jsonLdAddAsJsonArray(
            this,
            "type",
            mutableListOf<String>().apply {
                addAll(DEFAULT_JSONLD_TYPES)
                addAll(type)
            }
        )
        this.credentialSubject = credentialSubject
        JsonLDUtils.jsonLdAdd(this, "credentialSubject", credentialSubject)
        this.issuer = issuer
        JsonLDUtils.jsonLdAdd(this, "issuer", issuer.toString())
        this.issuanceDate = Date(issuanceDate.time/1000*1000)
        JsonLDUtils.jsonLdAdd(this, "issuanceDate", issuanceDate.toJsonLdString())
        this.proof = proof
    }

    override fun equals(other: Any?): Boolean {
        return if(other is Credential){
            contexts == other.contexts &&
                    types == other.types &&
                    credentialSubject == other.credentialSubject &&
                    issuer == other.issuer &&
                    issuanceDate == other.issuanceDate
        }else{
            false
        }
    }

}

