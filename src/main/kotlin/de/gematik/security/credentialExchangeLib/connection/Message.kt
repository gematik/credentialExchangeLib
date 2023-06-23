package de.gematik.security.credentialExchangeLib.connection

import kotlinx.serialization.Serializable

@Serializable
data class Message(val content: String, val type: MessageType? = null)

enum class MessageType {
    PLAIN_TEXT,
    INVITATION_ACCEPT,
    CREDENTIAL_OFFER,
    CREDENTIAL_REQUEST,
    CREDENTIAL_SUBMIT,
    BYE,
    CLOSED
}
