package de.gematik.security.credentialExchangeLib.connection

import java.net.URI

interface ConnectionFactory<T : Connection> {
    fun listen(
        handler: suspend (T) -> Unit
    )

    fun listen(
        serviceEndpoint: URI,
        handler: suspend (T) -> Unit
    )

    fun stopListening(
        serviceEndpoint: URI? = null
    )

    suspend fun connect(
        ownUri: URI? = null,
        invitationId: String? = null,
        firstProtocolMessage: Message? = null,
        handler: suspend (T) -> Unit
    )

    suspend fun connect(
        remoteUri: URI,
        ownUri: URI? = null,
        invitationId: String? = null,
        firstProtocolMessage: Message? = null,
        handler: suspend (T) -> Unit
    )
}