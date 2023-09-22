package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.websocket.WsConnection
import de.gematik.security.credentialExchangeLib.extensions.createUri
import java.net.URI
import java.util.*

abstract class ProtocolFactory<T : Protocol> {
    abstract fun listen(
        connectionFactory: ConnectionFactory<*>,
        serviceEndpoint : URI = createUri("0.0.0.0", 8090, "/ws"),
        handler: suspend (T) -> Unit
    )

    fun stopListening(
        serviceEndpoint : URI? = null
    ){
        WsConnection.stopListening(serviceEndpoint)
    }

    abstract suspend fun bind(
        connection: Connection,
        handler: suspend (T) -> Unit
    )

    abstract suspend fun connect(
        connectionFactory: ConnectionFactory<*>,
        to: URI? = null,
        from: URI? = null,
        invitationId: UUID? = null,
        firstProtocolMessage: Message? = null,
        handler: suspend (T) -> Unit
    )
}