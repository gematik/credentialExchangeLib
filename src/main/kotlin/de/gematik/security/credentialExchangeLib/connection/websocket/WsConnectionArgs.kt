package de.gematik.security.credentialExchangeLib.connection.websocket

import de.gematik.security.credentialExchangeLib.connection.ConnectionArgs
import de.gematik.security.credentialExchangeLib.extensions.createUri
import java.net.URI

data class WsConnectionArgs (
    override val endpoint: URI = createUri("0.0.0.0", 8090, "/ws")
) : ConnectionArgs