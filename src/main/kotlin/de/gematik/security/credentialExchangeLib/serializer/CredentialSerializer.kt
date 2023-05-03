package de.gematik.security.mobilewallet.serializer

import de.gematik.security.mobilewallet.types.Credential
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object CredentialSerializer : KSerializer<Credential> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Credential", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Credential) {
        encoder.encodeString(value.toJson())
    }

    override fun deserialize(decoder: Decoder): Credential {
        return Credential.fromJson(decoder.decodeString())?: throw SerializationException("can not deserialize credential")
    }
}