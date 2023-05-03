package de.gematik.security.mobilewallet.types

import de.gematik.security.mobilewallet.serializer.URISerializer
import de.gematik.security.mobilewallet.serializer.UUIDSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

val MESSAGE_INVITATION = URI.create("https://gematik.de/out-of-band/1.0/invitation")
val SERVICE_PX_OVER_HTTP = "px-over-http"

@Serializable
data class Invitation(
    @SerialName("@type") val atType: @Serializable(with = URISerializer::class) URI,
    @SerialName("@id") val atId: @Serializable(with = UUIDSerializer::class) UUID,
    val label: String,
    val goal_code: String,
    val goal: String,
    val services: List<Service>
)

@Serializable
data class Service(
    val type: String,
    val serviceEndpoint: @Serializable(with = URISerializer::class) URI
)