package de.gematik.security.credentialExchangeLib.connection

import java.net.URI
import java.util.*

interface ConnectionFactory<T : Connection> {
    fun listen(
        to: URI? = null,
        handler: suspend (T) -> Unit
    )

    fun stopListening(
        to: URI? = null
    )

    suspend fun connect(
        to: URI? = null,
        from: URI? = null,
        invitationId: UUID? = null,
        firstProtocolMessage: Message? = null,
        handler: suspend (T) -> Unit
    )
}