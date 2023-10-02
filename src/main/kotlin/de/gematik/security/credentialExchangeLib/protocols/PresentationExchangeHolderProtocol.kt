package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.MessageType
import de.gematik.security.credentialExchangeLib.json
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.net.URI
import java.security.InvalidParameterException

class PresentationExchangeHolderProtocol private constructor(connection: Connection) : Protocol(connection) {

    enum class State {
        INITIALIZED,

        SEND_PRESENTATION_OFFER,
        WAIT_FOR_PRESENTATION_REQUEST,
        SUBMIT_PRESENTATION,
        PRESENTATION_SUBMITTED,

        CLOSED
    }

    @Serializable
    data class ProtocolState(
        var state: State = State.INITIALIZED,
        var invitationId: String? = null,
        var offer: PresentationOffer? = null,
        var request: PresentationRequest? = null,
        var submit: PresentationSubmit? = null,
        var close: Close? = null
    )

    val protocolState = ProtocolState(state = State.SEND_PRESENTATION_OFFER, invitationId = connection.invitationId)

    companion object : ProtocolFactory<PresentationExchangeHolderProtocol>() {
        override fun listen(
            connectionFactory: ConnectionFactory<*>,
            serviceEndpoint: URI,
            handler: suspend (PresentationExchangeHolderProtocol) -> Unit
        ) {
            return connectionFactory.listen(serviceEndpoint) {
                PresentationExchangeHolderProtocol(it).also {
                    protocols[it.id] = it
                }.use {
                    handler(it)
                }
            }
        }

        override suspend fun bind(
            connection: Connection,
            handler: suspend (PresentationExchangeHolderProtocol) -> Unit
        ) {
            PresentationExchangeHolderProtocol(connection).also {
                protocols[it.id] = it
            }.use {
                handler(it)
            }
        }

        override suspend fun connect(
            connectionFactory: ConnectionFactory<*>,
            to: URI,
            from: URI?,
            invitationId: String?,
            firstProtocolMessage: Message?,
            handler: suspend (PresentationExchangeHolderProtocol) -> Unit
        ) {
            connectionFactory.connect(to, from, invitationId, firstProtocolMessage) {
                PresentationExchangeHolderProtocol(it).also {
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
                MessageType.PRESENTATION_REQUEST -> {
                    check(protocolState.state == State.WAIT_FOR_PRESENTATION_REQUEST || protocolState.state == State.SEND_PRESENTATION_OFFER) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromJsonElement<PresentationRequest>(message.content).also {
                        protocolState.request = it
                        protocolState.state = State.SUBMIT_PRESENTATION
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

    suspend fun sendOffer(presentationOffer: PresentationOffer) {
        check(protocolState.state == State.SEND_PRESENTATION_OFFER)
        protocolState.offer = presentationOffer
        connection.send(
            Message(
                json.encodeToJsonElement(presentationOffer).jsonObject,
                MessageType.PRESENTATION_OFFER
            )
        )
        protocolState.state = State.WAIT_FOR_PRESENTATION_REQUEST
    }

    suspend fun submitPresentation(presentationSubmit: PresentationSubmit) {
        check(protocolState.state == State.SUBMIT_PRESENTATION)
        protocolState.submit = presentationSubmit
        connection.send(Message(json.encodeToJsonElement(presentationSubmit).jsonObject, MessageType.PRESENTATION_SUBMIT))
        protocolState.state = State.PRESENTATION_SUBMITTED
    }

    override fun close() {
        protocolState.state = State.CLOSED
        protocols.remove(id)
    }
}