package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
open class LdObject {
    constructor(id: String? = null, atContext: List<URI>? = null, type: List<String>){
        this.id = id
        this.atContext = atContext
        this.type = type
    }
    var id: String? = null
    @SerialName("@context") private var _atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>? = null
    var atContext
        get() = _atContext?.map { URI.create(it) }
        set(value) {
            _atContext = value?.map { it.toString() }
        }
    @Required var type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>

    abstract class Defaults {

        abstract val DEFAULT_JSONLD_CONTEXTS: List<URI>
        abstract val DEFAULT_JSONLD_TYPES: List<String>
    }
}