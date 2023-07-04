package de.gematik.security.credentialExchangeLib.connection

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
data class Message(val content: JsonObject, val type: MessageType? = null)

enum class MessageType {
    INVITATION_ACCEPT,
    CREDENTIAL_OFFER,
    CREDENTIAL_REQUEST,
    CREDENTIAL_SUBMIT,
    PRESENTATION_OFFER,
    PRESENTATION_REQUEST,
    PRESENTATION_SUBMIT,
    CLOSE
}
