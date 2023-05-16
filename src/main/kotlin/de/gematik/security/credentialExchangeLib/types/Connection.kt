package de.gematik.security.mobilewallet.types

import kotlinx.serialization.Serializable

@Serializable
data class Connection(
    val invitation: Invitation
)


