package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.MessageType
import de.gematik.security.credentialExchangeLib.json
import io.ktor.server.engine.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.security.InvalidParameterException

class CredentialExchangeIssuerProtocol private constructor(val connection: Connection) : Protocol() {

    enum class State {
        INITIALIZED,

        SEND_CREDENTIAL_OFFER,
        WAIT_FOR_CREDENTIAL_REQUEST,
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
        var submit: CredentialSubmit? = null,
        var close: Close? = null
    )

    val protocolState = ProtocolState()

    companion object : ProtocolFactory<CredentialExchangeIssuerProtocol> {
        override fun listen(
            connectionFactory: ConnectionFactory<*>,
            host: String,
            port: Int,
            path: String,
            handler: suspend (CredentialExchangeIssuerProtocol) -> Unit
        ): ApplicationEngine {
            return connectionFactory.listen(host, port, path) {
                CredentialExchangeIssuerProtocol(it).also {
                    protocols[it.id] = it
                }.use {
                    handler(it)
                }
            }
        }

        override suspend fun connect(
            connectionFactory: ConnectionFactory<*>,
            host: String,
            port: Int,
            path: String,
            handler: suspend (CredentialExchangeIssuerProtocol) -> Unit
        ) {
            connectionFactory.connect(host, port, path) {
                val oob = path.substringAfter("oob=", "").substringBefore("&")
                val invitation = if (oob.isEmpty()) null else Invitation.fromBase64(oob)
                CredentialExchangeIssuerProtocol(it).also {
                    protocols[it.id] = it
                }.use {
                    invitation?.let { inv -> it.connected(inv) }
                    handler(it)
                }
            }
        }
    }

    override suspend fun receive(): LdObject {
        var pm: LdObject? = null
        while (pm == null) {
            val message = connection.receive()
            pm = when (message.type) {
                MessageType.INVITATION_ACCEPT -> {
                    check(protocolState.state == State.INITIALIZED) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromJsonElement<Invitation>(message.content).also {
                        protocolState.invitation = it
                        protocolState.state = State.SEND_CREDENTIAL_OFFER
                    }
                }

                MessageType.CREDENTIAL_REQUEST -> {
                    check(protocolState.state == State.WAIT_FOR_CREDENTIAL_REQUEST) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromJsonElement<CredentialRequest>(message.content).also {
                        protocolState.request = it
                        protocolState.state = State.SUBMIT_CREDENTIAL
                    }
                }

                MessageType.CLOSE -> {
                    json.decodeFromJsonElement<Close>(message.content).also {
                        protocolState.close = it
                        protocolState.state = State.CLOSED
                    }
                }

                else -> throw InvalidParameterException("wrong message type: ${message.type?.name}")
            }
        }
        return pm
    }

    override fun connected(invitation: Invitation) {
        check(protocolState.state == State.INITIALIZED)
        protocolState.invitation = invitation
        protocolState.state = State.SEND_CREDENTIAL_OFFER
    }

    suspend fun sendOffer(credentialOffer: CredentialOffer) {
        check(protocolState.state == State.SEND_CREDENTIAL_OFFER)
        protocolState.offer = credentialOffer
        connection.send(Message(json.encodeToJsonElement(credentialOffer).jsonObject, MessageType.CREDENTIAL_OFFER))
        protocolState.state = State.WAIT_FOR_CREDENTIAL_REQUEST
    }

    suspend fun submitCredential(credentialSubmit: CredentialSubmit) {
        check(protocolState.state == State.SUBMIT_CREDENTIAL)
        protocolState.submit = credentialSubmit
        connection.send(
            Message(
                json.encodeToJsonElement(credentialSubmit).jsonObject,
                MessageType.CREDENTIAL_SUBMIT
            )
        )
        protocolState.state = State.CREDENTIAL_SUBMITTED
    }

    override fun close() {
        protocolState.state = State.CLOSED
        protocols.remove(id)
    }
}