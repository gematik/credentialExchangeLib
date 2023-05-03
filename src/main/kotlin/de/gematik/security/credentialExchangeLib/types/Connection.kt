package de.gematik.security.mobilewallet.types

import de.gematik.security.mobilewallet.serializer.URLSerializer
import de.gematik.security.mobilewallet.serializer.UUIDSerializer
import kotlinx.serialization.Serializable
import java.net.URL
import java.util.*

@Serializable
data class Connection(
    val invitation: Invitation
)


