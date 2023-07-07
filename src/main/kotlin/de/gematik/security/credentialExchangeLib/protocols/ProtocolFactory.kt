package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import io.ktor.server.engine.*

interface ProtocolFactory<T : Protocol> {
    fun listen(
        connectionFactory: ConnectionFactory<*>,
        host: String = "0.0.0.0",
        port: Int = 8090,
        path: String = "ws",
        handler: suspend (T) -> Unit
    ): ApplicationEngine

    suspend fun connect(
        connectionFactory: ConnectionFactory<*>,
        host: String = "127.0.0.1",
        port: Int = 8090,
        path: String = "ws",
        handler: suspend (T) -> Unit
    )
}