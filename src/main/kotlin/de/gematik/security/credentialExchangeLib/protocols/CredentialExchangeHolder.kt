package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.MessageType
import de.gematik.security.credentialExchangeLib.json
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonPrimitive
import java.security.InvalidParameterException

class CredentialExchangeHolder private constructor(val connection: Connection) {

    enum class State {
        INITIALIZED,
        WAIT_FOR_OFFER,
        SEND_REQUEST,
        WAIT_FOR_CREDENTIAL,
        CREDENTIAL_RECEIVED,
        CLOSED
    }

    @Serializable
    data class ProtocolState(
        var state: State = State.INITIALIZED,
        var invitation: Invitation? = null,
        var offer: CredentialOffer? = null,
        var request: CredentialRequest? = null,
        var submit: CredentialSubmit? = null
    )

    val protocolState = ProtocolState()

    companion object Factory {
        fun listen(factory: ConnectionFactory, protocolHandler: suspend (CredentialExchangeHolder) -> Unit) {
            factory.listen {
                protocolHandler(CredentialExchangeHolder(it))
            }
        }

        fun connect(
            factory: ConnectionFactory,
            host: String,
            port: Int,
            protocolHandler: suspend (CredentialExchangeHolder) -> Unit
        ) {
            factory.connect(host, port) {
                protocolHandler(CredentialExchangeHolder(it))
            }
        }
    }

    suspend fun receive(): LdObject {
        var pm: LdObject? = null
        while (pm == null) {
            val message = connection.receive()
            pm = when (message.type) {
                MessageType.CREDENTIAL_OFFER -> {
                    check(protocolState.state == State.WAIT_FOR_OFFER) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromString<CredentialOffer>(message.content).also {
                        protocolState.offer = it
                        protocolState.state = State.SEND_REQUEST
                    }
                }

                MessageType.CREDENTIAL_SUBMIT -> {
                    check(protocolState.state == State.WAIT_FOR_CREDENTIAL) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromString<CredentialSubmit>(message.content).also {
                        protocolState.submit = it
                        protocolState.state = State.CREDENTIAL_RECEIVED
                    }
                }

                MessageType.BYE -> JsonLdObject(
                    mapOf(
                        "error" to JsonPrimitive("coonection closed by peer")
                    )
                )

                else -> throw InvalidParameterException("wrong message type: ${message.type?.name}")
            }
        }
        return pm
    }

    suspend fun sendInvitation(invitation: Invitation) {
        check(protocolState.state == State.INITIALIZED)
        protocolState.invitation = invitation
        connection.send(Message(json.encodeToString(invitation), MessageType.INVITATION_ACCEPT))
        protocolState.state = State.WAIT_FOR_OFFER
    }

    suspend fun requestCredential(credentialRequest: CredentialRequest) {
        check(protocolState.state == State.SEND_REQUEST)
        protocolState.request = credentialRequest
        connection.send(Message(json.encodeToString(credentialRequest), MessageType.CREDENTIAL_REQUEST))
        protocolState.state = State.WAIT_FOR_CREDENTIAL
    }

    suspend fun close() {
        protocolState.state = State.CLOSED
        connection.close()
    }
}