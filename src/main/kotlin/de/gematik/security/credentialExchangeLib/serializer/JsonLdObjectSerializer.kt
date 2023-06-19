package de.gematik.security.credentialExchangeLib.serializer

import de.gematik.security.credentialExchangeLib.protocols.JsonLdObject
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject

object JsonLdObjectSerializer : KSerializer<JsonLdObject> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("JsonLdObject", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JsonLdObject) {
        encoder.encodeSerializableValue( JsonObject.serializer(), JsonObject(value))
    }

    override fun deserialize(decoder: Decoder): JsonLdObject {
        return JsonLdObject(decoder.decodeSerializableValue(JsonObject.serializer()))
    }
}