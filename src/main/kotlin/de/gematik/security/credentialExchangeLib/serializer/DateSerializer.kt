package de.gematik.security.credentialExchangeLib.serializer

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*


object DateSerializer : KSerializer<Date> {

    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ").apply {
        this.withZone(ZoneId.of("UTC"))
    }

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Date) {
        val zonedDateTime = ZonedDateTime.ofInstant(value.toInstant(),ZoneId.of("UTC"))
        encoder.encodeString( zonedDateTime.format(DateTimeFormatter.ISO_INSTANT))
    }

    override fun deserialize(decoder: Decoder): Date {
        return Date.from(ZonedDateTime.parse(decoder.decodeString()).toInstant());
    }
}