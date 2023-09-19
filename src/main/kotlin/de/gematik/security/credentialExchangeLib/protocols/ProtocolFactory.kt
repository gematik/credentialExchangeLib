package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionArgs
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.websocket.WsConnection
import de.gematik.security.credentialExchangeLib.connection.websocket.WsConnectionArgs
import de.gematik.security.credentialExchangeLib.extensions.createUri
import java.net.URI

abstract class ProtocolFactory<T : Protocol> {
    abstract fun listen(
        connectionFactory: ConnectionFactory<*>,
        connectionArgs : ConnectionArgs = WsConnectionArgs(),
        handler: suspend (T) -> Unit
    )

    fun stopListening(
        connectionArgs : ConnectionArgs = WsConnectionArgs()
    ){
        WsConnection.stopListening(connectionArgs)
    }

    abstract suspend fun bind(
        connection: Connection,
        invitation: Invitation,
        handler: suspend (T) -> Unit
    )

    abstract suspend fun connect(
        connectionFactory: ConnectionFactory<*>,
        connectionArgs : ConnectionArgs = WsConnectionArgs(createUri("127.0.0.1", 8090, "/ws")),
        handler: suspend (T) -> Unit
    )
}