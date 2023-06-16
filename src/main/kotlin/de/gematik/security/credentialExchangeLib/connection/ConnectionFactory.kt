package de.gematik.security.credentialExchangeLib.connection

import io.ktor.server.engine.*

interface ConnectionFactory {
    fun listen(wait: Boolean = false, connectionHandler: suspend (Connection) -> Unit) : ApplicationEngine
    fun connect(host: String, port: Int, wait: Boolean = false, connectionHandler: suspend (Connection) -> Unit)
}