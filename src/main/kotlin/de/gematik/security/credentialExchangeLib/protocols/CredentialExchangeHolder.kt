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
        fun listen(
            host: String = "0.0.0.0",
            port: Int = 8090,
            path: String = "ws",
            factory: ConnectionFactory, protocolHandler: suspend (CredentialExchangeHolder) -> Unit
        ) : ApplicationEngine {
            return factory.listen(host, port, path) {
                protocolHandler(CredentialExchangeHolder(it))
            }
        }

        suspend fun connect(
            factory: ConnectionFactory,
            host: String = "127.0.0.1",
            port: Int = 8090,
            path: String = "ws",
            invitation: Invitation? = null,
            protocolHandler: suspend (CredentialExchangeHolder) -> Unit
        ) {
            check(!(path.contains("oob=") && invitation!=null))
            factory.connect(host, port, path + if(invitation!=null) "?oob=${invitation.toBase64()}" else "") {
                protocolHandler(CredentialExchangeHolder(it).apply {
                    invitation?.let{
                        protocolState.invitation = invitation
                        protocolState.state = State.WAIT_FOR_OFFER
                    }
                    if(path.contains("oob=")){
                        val oob = path.substringAfter("oob=").substringBefore("&")
                        protocolState.invitation = Invitation.fromBase64(oob)
                        protocolState.state = State.WAIT_FOR_OFFER
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
                        protocolState.state = State.WAIT_FOR_OFFER
                    }
                }

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