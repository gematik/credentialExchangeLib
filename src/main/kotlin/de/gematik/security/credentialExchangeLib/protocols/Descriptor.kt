package de.gematik.security.credentialExchangeLib.protocols

import kotlinx.serialization.Serializable

@Serializable
data class Descriptor(val id: String, val frame: Credential)
