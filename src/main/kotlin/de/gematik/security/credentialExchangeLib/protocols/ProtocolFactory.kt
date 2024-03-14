/*
 * Copyright 2021-2024, gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.websocket.WsConnection
import de.gematik.security.credentialExchangeLib.extensions.createUri
import java.net.URI

abstract class ProtocolFactory<T : Protocol> {
    abstract fun listen(
        connectionFactory: ConnectionFactory<*>,
        serviceEndpoint : URI = createUri("0.0.0.0", 8090, "/ws"),
        handler: suspend (T) -> Unit
    )

    fun stopListening(
        serviceEndpoint : URI? = null
    ){
        WsConnection.stopListening(serviceEndpoint)
    }

    abstract suspend fun bind(
        connection: Connection,
        handler: suspend (T) -> Unit
    )

    abstract suspend fun connect(
        connectionFactory: ConnectionFactory<*>,
        to: URI = createUri("127.0.0.1", 8090, "/ws"),
        from: URI? = null,
        invitationId: String? = null,
        firstProtocolMessage: Message? = null,
        handler: suspend (T) -> Unit
    )
}