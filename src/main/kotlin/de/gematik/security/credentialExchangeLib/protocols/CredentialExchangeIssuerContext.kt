package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.MessageType
import de.gematik.security.credentialExchangeLib.json
import io.ktor.server.engine.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.security.InvalidParameterException

class CredentialExchangeIssuerContext private constructor(val connection: Connection) : Context() {

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

    companion object : ContextFactory<CredentialExchangeIssuerContext> {
        override fun listen (
            connectionFactory: ConnectionFactory<*>,
            host: String,
            port: Int,
            path: String,
            protocolHandler: suspend (CredentialExchangeIssuerContext) -> Unit
        ) : ApplicationEngine {
            return connectionFactory.listen(host, port, path) {
                newInstance(it).use {
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
            protocolHandler: suspend (CredentialExchangeIssuerContext) -> Unit
        ) {
            check(!(path.contains("oob=") && invitation!=null))
            connectionFactory.connect(host, port, path + if(invitation!=null) "?oob=${invitation.toBase64()}" else "") {
                newInstance(it).apply {
                    invitation?.let{
                        protocolState.invitation = invitation
                        protocolState.state = State.SEND_OFFER
                    }
                    if(path.contains("oob=")){
                        val oob = path.substringAfter("oob=").substringBefore("&")
                        protocolState.invitation = Invitation.fromBase64(oob)
                        protocolState.state = State.SEND_OFFER
                    }
                }.use {
                    protocolHandler(it)
                }
            }
        }

        private fun newInstance(connection: Connection) : CredentialExchangeIssuerContext {
            val context = CredentialExchangeIssuerContext(connection)
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
                        protocolState.state = State.SEND_OFFER
                    }
                }

                MessageType.CREDENTIAL_REQUEST -> {
                    check(protocolState.state == State.WAIT_FOR_REQUEST) { "invalid state: ${protocolState.state.name}" }
                    json.decodeFromJsonElement<CredentialRequest>(message.content).also {
                        protocolState.request = it
                        protocolState.state = State.SUBMIT_CREDENTIAL
                    }
                }

                MessageType.CLOSE -> JsonLdObject(message.content.toMap())

                else -> throw InvalidParameterException("wrong message type: ${message.type?.name}")
            }
        }
        return pm
    }

    suspend fun sendOffer(credentialOffer: CredentialOffer) {
        check(protocolState.state == State.SEND_OFFER)
        protocolState.offer = credentialOffer
        connection.send(Message(json.encodeToJsonElement(credentialOffer).jsonObject, MessageType.CREDENTIAL_OFFER))
        protocolState.state = State.WAIT_FOR_REQUEST
    }

    suspend fun submitCredential(credentialSubmit: CredentialSubmit) {
        check(protocolState.state == State.SUBMIT_CREDENTIAL)
        protocolState.submit = credentialSubmit
        connection.send(Message(json.encodeToJsonElement(credentialSubmit).jsonObject, MessageType.CREDENTIAL_SUBMIT))
        protocolState.state = State.CREDENTIAL_SUBMITTED
    }

    override fun close() {
        protocolState.state = State.CLOSED
        contexts.remove(id)
    }
}