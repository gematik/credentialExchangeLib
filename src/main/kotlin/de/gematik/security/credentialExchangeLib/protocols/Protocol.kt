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