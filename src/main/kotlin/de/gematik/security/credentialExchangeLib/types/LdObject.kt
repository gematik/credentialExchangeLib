package de.gematik.security.credentialExchangeLib.types

import java.net.URI

interface LdObject{
    val id: String?
    val atContext: List<URI>
    val type: List<String>?
    abstract class Defaults {
        abstract val DEFAULT_JSONLD_CONTEXTS: List<URI>
        abstract val DEFAULT_JSONLD_TYPES: List<String>
    }
}