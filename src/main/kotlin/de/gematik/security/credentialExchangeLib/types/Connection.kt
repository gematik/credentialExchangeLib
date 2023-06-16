package de.gematik.security.credentialExchangeLib.types

import kotlinx.serialization.Serializable

@Serializable
data class Connection(
    val invitation: Invitation
)


