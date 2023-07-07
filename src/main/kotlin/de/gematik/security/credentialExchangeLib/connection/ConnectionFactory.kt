package de.gematik.security.credentialExchangeLib.connection

import io.ktor.server.engine.*

interface ConnectionFactory<T : Connection> {
    fun listen(
        host: String = "0.0.0.0",
        port: Int = 8090,
        path: String = "ws",
        handler: suspend (T) -> Unit
    ): ApplicationEngine

    suspend fun connect(
        host: String = "127.0.0.1",
        port: Int = 8090,
        path: String = "ws",
        handler: suspend (T) -> Unit
    )
}