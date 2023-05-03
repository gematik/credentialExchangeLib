package de.gematik.security.mobilewallet.types

import de.gematik.security.mobilewallet.serializer.UUIDSerializer
import de.gematik.security.mobilewallet.types.Connection
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
data class ConnectionRecord(
    val recordId: @Serializable(with = UUIDSerializer::class) UUID,
    val connection: Connection
)
