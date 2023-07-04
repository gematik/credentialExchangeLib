package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.*
import de.gematik.security.credentialExchangeLib.json
import io.ktor.server.engine.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.security.InvalidParameterException

class PresentationExchangeVerifierContext private constructor(val connection: Connection) : Context() {

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

    companion object : ContextFactory<PresentationExchangeVerifierContext> {
        override fun listen(
            connectionFactory: ConnectionFactory<*>,
            host: String,
            port: Int,
            path: String,
            protocolHandler: suspend (PresentationExchangeVerifierContext) -> Unit
        ): ApplicationEngine {
            return connectionFactory.listen(host, port, path) {
                newInstance(it).use{
                    protocolHandler(it)
                }
            }
        }

        override suspend fun connect(
            connectionFactory: ConnectionFactory<*>,
            host: String,
            port: Int,
            path: String,
            invitation: Invitation?,
            protocolHandler: suspend (PresentationExchangeVerifierContext) -> Unit
        ) {
            check(!(path.contains("oob=") && invitation!=null))
            connectionFactory.connect(host, port, path + if(invitation!=null) "?oob=${invitation.toBase64()}" else "") {
                newInstance(it).apply {
                    invitation?.let{
                        protocolState.invitation = invitation
                        protocolState.state = State.WAIT_FOR_PRESENTATION_OFFER
                    }
                    if(path.contains("oob=")){
                        val oob = path.substringAfter("oob=").substringBefore("&")
                        protocolState.invitation = Invitation.fromBase64(oob)
                        protocolState.state = State.WAIT_FOR_PRESENTATION_OFFER
                    }
                }.use {
                    protocolHandler(it)
                }
            }
        }

        private fun newInstance(connection: Connection) : PresentationExchangeVerifierContext {
            val context = PresentationExchangeVerifierContext(connection)
            contexts[context.id] = context
            return context
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

    suspend fun sendInvitation(invitation: Invitation) {
        check(protocolState.state == State.INITIALIZED)
        protocolState.invitation = invitation
        connection.send(Message(json.encodeToJsonElement(invitation).jsonObject, MessageType.INVITATION_ACCEPT))
        protocolState.state = State.WAIT_FOR_PRESENTATION_OFFER
    }

    suspend fun requestPresentation(presentationRequest: PresentationRequest) {
        check(protocolState.state == State.SEND_PRESENTATION_REQUEST)
        protocolState.request = presentationRequest
        connection.send(Message(json.encodeToJsonElement(presentationRequest).jsonObject, MessageType.PRESENTATION_REQUEST))
        protocolState.state = State.WAIT_FOR_PRESENTATION
    }

    override fun close() {
        protocolState.state = State.CLOSED
        contexts.remove(id)
    }
}