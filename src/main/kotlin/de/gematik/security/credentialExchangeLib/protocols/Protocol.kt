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
import mu.KotlinLogging
import java.io.Closeable
import java.util.*

private val logger = KotlinLogging.logger {}

sealed class Protocol(val connection: Connection) : Closeable {

    companion object {
        @JvmStatic
        protected val protocols = Collections.synchronizedMap(mutableMapOf<UUID, Protocol>())
        fun getNumberOfProtocolInstances(): Int{
            return protocols.size
        }
        fun getProtocolInstance(id: UUID) : Protocol? {
            return protocols.get(id)
        }
    }

    val id : UUID = UUID.randomUUID()

    init{
        logger.info { "new protocol context: $id" }
    }

    abstract suspend fun receive() : LdObject
}