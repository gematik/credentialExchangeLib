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

package de.gematik.security.credentialExchangeLib.connection
import kotlinx.coroutines.channels.Channel
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mu.KotlinLogging
import java.io.Closeable
import java.util.*

private val logger = KotlinLogging.logger {}

abstract class Connection(val role: Role, val invitationId: String?) : Closeable {

    enum class Role {
        INVITER,
        INVITEE
    }

    val id : UUID = UUID.randomUUID()

    companion object {
        @JvmStatic
        protected val connections = Collections.synchronizedMap(mutableMapOf<UUID, Connection>())
        fun getNumberOfConnections(): Int{
            return connections.size
        }
        fun getConnection(id: UUID) : Connection? {
            return connections.get(id)
        }
    }

    init{
        logger.info { "new connection - role: $role, id: $id, invitationId: $invitationId" }
    }

    val channel = Channel<Message>(10)

    abstract suspend fun send(message: Message)

    suspend fun receive() : Message{
        return channel.receive().also{
            logger.debug { "receive from channel: ${Json.encodeToString(it)}" }
        }
    }

}