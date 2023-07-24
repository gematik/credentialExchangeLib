package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.WsConnection

abstract class ProtocolFactory<T : Protocol> {
    abstract fun listen(
        connectionFactory: ConnectionFactory<*>,
        host: String = "0.0.0.0",
        port: Int = 8090,
        path: String = "ws",
        handler: suspend (T) -> Unit
    )

    fun stopListening(
        host: String? = null,
        port: Int? = null,
    ){
        WsConnection.stopListening(host, port)
    }

    abstract suspend fun connect(
        connectionFactory: ConnectionFactory<*>,
        host: String = "127.0.0.1",
        port: Int = 8090,
        path: String = "ws",
        handler: suspend (T) -> Unit
    )
}