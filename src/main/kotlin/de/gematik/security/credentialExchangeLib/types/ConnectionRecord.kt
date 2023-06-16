package de.gematik.security.credentialExchangeLib.types

import de.gematik.security.credentialExchangeLib.serializer.UUIDSerializer
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
data class ConnectionRecord(
    val recordId: @Serializable(with = UUIDSerializer::class) UUID,
    val connection: Connection
)
