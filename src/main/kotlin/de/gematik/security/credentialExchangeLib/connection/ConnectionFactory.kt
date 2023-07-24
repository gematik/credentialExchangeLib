package de.gematik.security.credentialExchangeLib.connection

interface ConnectionFactory<T : Connection> {
    fun listen(
        host: String = "0.0.0.0",
        port: Int = 8090,
        path: String = "ws",
        handler: suspend (T) -> Unit
    )

    fun stopListening(
        host: String? = null,
        port: Int? = null
    )

    suspend fun connect(
        host: String = "127.0.0.1",
        port: Int = 8090,
        path: String = "ws",
        handler: suspend (T) -> Unit
    )
}