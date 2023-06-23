package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.MessageType
import de.gematik.security.credentialExchangeLib.json
import io.ktor.server.engine.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import java.security.InvalidParameterException

class CredentialExchangeIssuer private constructor(val connection: Connection) {

    enum class State {
        INITIALIZED,
        SEND_OFFER,
        WAIT_FOR_REQUEST,
        SUBMIT_CREDENTIAL,
        CREDENTIAL_SUBMITTED,
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
        fun listen (
            factory: ConnectionFactory,
            host: String = "0.0.0.0",
            port: Int = 8090,
            path: String = "ws",
            protocolHandler: suspend (CredentialExchangeIssuer) -> Unit
        ) : ApplicationEngine {
            return factory.listen(host, port, path) {
                protocolHandler(CredentialExchangeIssuer(it))
            }
        }

        suspend fun connect(
            factory: ConnectionFactory,
            host: String = "127.0.0.1",
            port: Int = 8090,
            path: String = "ws",
            invitation: Invitation? = null,
            protocolHandler: suspend (CredentialExchangeIssuer) -> Unit
        ) {
            check(!(path.contains("oob=") && invitation!=null))
            factory.connect(host, port, path + if(invitation!=null) "?oob=${invitation.toBase64()}" else "") {
                protocolHandler(CredentialExchangeIssuer(it).apply {
                    invitation?.let{
                        protocolState.invitation = invitation
                        protocolState.state = State.SEND_OFFER
                    }
                    if(path.contains("oob=")){
                        val oob = path.substringAfter("oob=").substringBefore("&")
                        protocolState.invitation = Invitation.fromBase64(oob)
                        protocolState.state = State.SEND_OFFER
                    }
                })
            }
        }
    }

    suspend fun receive(): LdObject {
        var pm: LdObject? = null
        while (pm == null) {
            val message = connection.receive()
            pm = when (message.type) {
                MessageType.INVITATION_ACCEPT -> {
                    check(protocolState.state == State.INITIALIZED) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromString<Invitation>(message.content).also {
                        protocolState.invitation = it
                        protocolState.state = State.SEND_OFFER
                    }
                }

                MessageType.CREDENTIAL_REQUEST -> {
                    check(protocolState.state == State.WAIT_FOR_REQUEST) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromString<CredentialRequest>(message.content).also {
                        protocolState.request = it
                        protocolState.state = State.SUBMIT_CREDENTIAL
                    }
                }

                MessageType.BYE -> JsonLdObject(
                    mapOf(
                        "type" to JsonArray(listOf(JsonPrimitive("Error"))),
                        "description" to JsonPrimitive("Bye from peer with message: ${message.content}")
                    )
                )

                MessageType.CLOSED -> JsonLdObject(
                    mapOf(
                        "type" to JsonArray(listOf(JsonPrimitive("Error"))),
                        "description" to JsonPrimitive("Connection closed")
                    )
                )

                else -> throw InvalidParameterException("wrong message type: ${message.type?.name}")
            }
        }
        return pm
    }

    suspend fun sendOffer(credentialOffer: CredentialOffer) {
        check(protocolState.state == State.SEND_OFFER)
        protocolState.offer = credentialOffer
        connection.send(Message(json.encodeToString(credentialOffer), MessageType.CREDENTIAL_OFFER))
        protocolState.state = State.WAIT_FOR_REQUEST
    }

    suspend fun submitCredential(credentialSubmit: CredentialSubmit) {
        check(protocolState.state == State.SUBMIT_CREDENTIAL)
        protocolState.submit = credentialSubmit
        connection.send(Message(json.encodeToString(credentialSubmit), MessageType.CREDENTIAL_SUBMIT))
        protocolState.state = State.CREDENTIAL_SUBMITTED
    }

    suspend fun close() {
        protocolState.state = State.CLOSED
        connection.close()
    }
}