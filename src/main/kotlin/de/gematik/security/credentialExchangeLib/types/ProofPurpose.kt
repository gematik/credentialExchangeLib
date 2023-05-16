package de.gematik.security.credentialExchangeLib.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class ProofPurpose {
    @SerialName("assertionMethod") ASSERTION_METHOD,
    @SerialName("authentication") AUTHENTICATION
}