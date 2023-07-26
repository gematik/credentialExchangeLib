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
import java.security.InvalidParameterException

class PresentationExchangeVerifierProtocol private constructor(connection: Connection) : Protocol(connection) {

    enum class State {
        INITIALIZED,

        WAIT_FOR_PRESENTATION_OFFER,
        SEND_PRESENTATION_REQUEST,
        WAIT_FOR_PRESENTATION,
        PRESENTATION_RECEIVED,

        CLOSED
    }

    @Serializable
    data class ProtocolState(
        var state: State = State.INITIALIZED,
        var invitation: Invitation? = null,
        var offer: PresentationOffer? = null,
        var request: PresentationRequest? = null,
        var submit: PresentationSubmit? = null,
        var close: Close?=null
    )

    val protocolState = ProtocolState()

    companion object : ProtocolFactory<PresentationExchangeVerifierProtocol>() {
        override fun listen(
            connectionFactory: ConnectionFactory<*>,
            host: String,
            port: Int,
            path: String,
            handler: suspend (PresentationExchangeVerifierProtocol) -> Unit
        ) {
            connectionFactory.listen(host, port, path) {
                PresentationExchangeVerifierProtocol(it).also {
                    protocols[it.id] = it
                }.use {
                    handler(it)
                }
            }
        }

        override suspend fun bind(
            connection: Connection,
            invitation: Invitation,
            handler: suspend (PresentationExchangeVerifierProtocol) -> Unit
        ) {
            PresentationExchangeVerifierProtocol(connection).also {
                protocols[it.id] = it
                it.connected(invitation)
            }.use {
                handler(it)
            }
        }

        override suspend fun connect(
            connectionFactory: ConnectionFactory<*>,
            host: String,
            port: Int,
            path: String,
            handler: suspend (PresentationExchangeVerifierProtocol) -> Unit
        ) {
            connectionFactory.connect(host, port, path) {
                val oob = path.substringAfter("oob=", "").substringBefore("&")
                val invitation = if (oob.isEmpty()) null else Invitation.fromBase64(oob)
                PresentationExchangeVerifierProtocol(it).also {
                    protocols[it.id] = it
                }.use {
                    invitation?.let{inv -> it.connected(inv)}
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
                        protocolState.state = State.WAIT_FOR_PRESENTATION_OFFER
                    }
                }

                MessageType.PRESENTATION_OFFER -> {
                    check(protocolState.state == State.WAIT_FOR_PRESENTATION_OFFER) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromJsonElement<PresentationOffer>(message.content).also {
                        protocolState.offer = it
                        protocolState.state = State.SEND_PRESENTATION_REQUEST
                    }
                }

                MessageType.PRESENTATION_SUBMIT -> {
                    check(protocolState.state == State.WAIT_FOR_PRESENTATION) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromJsonElement<PresentationSubmit>(message.content).also {
                        protocolState.submit = it
                        protocolState.state = State.PRESENTATION_RECEIVED
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
        protocolState.state = State.WAIT_FOR_PRESENTATION_OFFER
    }

    suspend fun sendInvitation(invitation: Invitation) {
        check(protocolState.state == State.INITIALIZED)
        protocolState.invitation = invitation
        connection.send(Message(json.encodeToJsonElement(invitation).jsonObject, MessageType.INVITATION_ACCEPT))
        protocolState.state = State.WAIT_FOR_PRESENTATION_OFFER
    }

    suspend fun requestPresentation(presentationRequest: PresentationRequest) {
        check(protocolState.state == State.SEND_PRESENTATION_REQUEST || protocolState.state == State.WAIT_FOR_PRESENTATION_OFFER)
        protocolState.request = presentationRequest
        connection.send(Message(json.encodeToJsonElement(presentationRequest).jsonObject, MessageType.PRESENTATION_REQUEST))
        protocolState.state = State.WAIT_FOR_PRESENTATION
    }

    override fun close() {
        protocolState.state = State.CLOSED
        protocols.remove(id)
    }
}