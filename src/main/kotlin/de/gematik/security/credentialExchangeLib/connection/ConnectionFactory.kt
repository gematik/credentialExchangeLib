package de.gematik.security.credentialExchangeLib.connection

import de.gematik.security.credentialExchangeLib.connection.websocket.WsConnectionArgs
import java.net.URI

interface ConnectionFactory<T : Connection> {
    fun listen(
        connectionArgs: ConnectionArgs? = null,
        handler: suspend (T) -> Unit
    )

    fun stopListening(
        connectionArgs: ConnectionArgs? = null
    )

    suspend fun connect(
        connectionArgs: ConnectionArgs? = null,
        handler: suspend (T) -> Unit
    )
}