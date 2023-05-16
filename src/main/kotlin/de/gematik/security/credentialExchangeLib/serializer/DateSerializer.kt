package de.gematik.security.credentialExchangeLib.serializer

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.text.SimpleDateFormat
import java.util.*

object DateSerializer : KSerializer<Date> {

    val simpleDateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX").apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Date) {
        encoder.encodeString(simpleDateFormat.format(value))
    }

    override fun deserialize(decoder: Decoder): Date {
        return simpleDateFormat.parse(decoder.decodeString())
    }
}