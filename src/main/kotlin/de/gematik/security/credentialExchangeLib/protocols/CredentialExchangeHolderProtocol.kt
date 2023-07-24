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

class CredentialExchangeHolderProtocol private constructor(val connection: Connection) : Protocol() {

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
        var invitation: Invitation? = null,
        var offer: CredentialOffer? = null,
        var request: CredentialRequest? = null,
        var submit: CredentialSubmit? = null,
        var close: Close? = null
    )

    val protocolState = ProtocolState()

    companion object : ProtocolFactory<CredentialExchangeHolderProtocol>() {
        override fun listen(
            connectionFactory: ConnectionFactory<*>,
            host: String,
            port: Int,
            path: String,
            handler: suspend (CredentialExchangeHolderProtocol) -> Unit
        ) {
            connectionFactory.listen(host, port, path) {
                CredentialExchangeHolderProtocol(it).also {
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
            handler: suspend (CredentialExchangeHolderProtocol) -> Unit
        ) {
            connectionFactory.connect(host, port, path) {
                val oob = path.substringAfter("oob=", "").substringBefore("&")
                val invitation = if (oob.isEmpty()) null else Invitation.fromBase64(oob)
                CredentialExchangeHolderProtocol(it).also {
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
                        protocolState.state = State.WAIT_FOR_CREDENTIAL_OFFER
                    }
                }

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

    override fun connected(invitation: Invitation) {
        check(protocolState.state == State.INITIALIZED)
        protocolState.invitation = invitation
        protocolState.state = State.WAIT_FOR_CREDENTIAL_OFFER
    }

    suspend fun sendInvitation(invitation: Invitation) {
        check(protocolState.state == State.INITIALIZED)
        protocolState.invitation = invitation
        connection.send(Message(json.encodeToJsonElement(invitation).jsonObject, MessageType.INVITATION_ACCEPT))
        protocolState.state = State.WAIT_FOR_CREDENTIAL_OFFER
    }

    suspend fun requestCredential(credentialRequest: CredentialRequest) {
        check(protocolState.state == State.SEND_CREDENTIAL_REQUEST)
        protocolState.request = credentialRequest
        connection.send(Message(json.encodeToJsonElement(credentialRequest).jsonObject, MessageType.CREDENTIAL_REQUEST))
        protocolState.state = State.WAIT_FOR_CREDENTIAL
    }

    override fun close() {
        protocolState.state = State.CLOSED
        protocols.remove(id)
    }
}