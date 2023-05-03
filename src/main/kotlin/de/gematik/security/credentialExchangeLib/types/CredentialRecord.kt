package de.gematik.security.mobilewallet.types

import de.gematik.security.mobilewallet.serializer.UUIDSerializer
import de.gematik.security.mobilewallet.types.Credential
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
data class CredentialRecord(
    val recordId: @Serializable(with = UUIDSerializer::class) UUID,
    val credential: Credential
)
