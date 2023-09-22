package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.MessageType
import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.serializer.UUIDSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.net.URI
import java.security.InvalidParameterException
import java.util.*

class CredentialExchangeHolderProtocol private constructor(connection: Connection) : Protocol(connection) {

    enum class State {
        INITIALIZED,

        WAIT_FOR_CREDENTIAL_OFFER,
        SEND_CREDENTIAL_REQUEST,
        WAIT_FOR_CREDENTIAL,
        CREDENTIAL_RECEIVED,

        CLOSED
    }

    @Serializable
    data class ProtocolState(
        var state: State = State.INITIALIZED,
        var invitationId: @Serializable(with = UUIDSerializer::class) UUID? = null,
        var offer: CredentialOffer? = null,
        var request: CredentialRequest? = null,
        var submit: CredentialSubmit? = null,
        var close: Close? = null
    )

    val protocolState = ProtocolState(state = State.WAIT_FOR_CREDENTIAL_OFFER, invitationId = connection.invitationId)

    companion object : ProtocolFactory<CredentialExchangeHolderProtocol>() {
        override fun listen(
            connectionFactory: ConnectionFactory<*>,
            serviceEndpoint: URI,
            handler: suspend (CredentialExchangeHolderProtocol) -> Unit
        ) {
            connectionFactory.listen(serviceEndpoint) {
                CredentialExchangeHolderProtocol(it).also {
                    protocols[it.id] = it
                }.use {
                    handler(it)
                }
            }
        }

        override suspend fun bind(
            connection: Connection,
            handler: suspend (CredentialExchangeHolderProtocol) -> Unit
        ) {
            CredentialExchangeHolderProtocol(connection).also {
                protocols[it.id] = it
            }.use {
                handler(it)
            }
        }

        override suspend fun connect(
            connectionFactory: ConnectionFactory<*>,
            to: URI?,
            from: URI?,
            invitationId: UUID?,
            firstProtocolMessage: Message?,
            handler: suspend (CredentialExchangeHolderProtocol) -> Unit
        ) {
            connectionFactory.connect(to, from, invitationId, firstProtocolMessage) {
                CredentialExchangeHolderProtocol(it).also {
                    protocols[it.id] = it
                }.use {
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
                MessageType.CREDENTIAL_OFFER -> {
                    check(protocolState.state == State.WAIT_FOR_CREDENTIAL_OFFER) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromJsonElement<CredentialOffer>(message.content).also {
                        protocolState.offer = it
                        protocolState.state = State.SEND_CREDENTIAL_REQUEST
                    }
                }

                MessageType.CREDENTIAL_SUBMIT -> {
                    check(protocolState.state == State.WAIT_FOR_CREDENTIAL) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromJsonElement<CredentialSubmit>(message.content).also {
                        protocolState.submit = it
                        protocolState.state = State.CREDENTIAL_RECEIVED
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

    suspend fun requestCredential(credentialRequest: CredentialRequest) {
        check(protocolState.state == State.SEND_CREDENTIAL_REQUEST || protocolState.state == State.WAIT_FOR_CREDENTIAL_OFFER)
        protocolState.request = credentialRequest
        connection.send(Message(json.encodeToJsonElement(credentialRequest).jsonObject, MessageType.CREDENTIAL_REQUEST))
        protocolState.state = State.WAIT_FOR_CREDENTIAL
    }

    override fun close() {
        protocolState.state = State.CLOSED
        protocols.remove(id)
    }
}