package de.gematik.security.credentialExchangeLib.connection
import mu.KotlinLogging
import java.io.Closeable
import java.util.*

sealed class Connection : Closeable {

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

    val logger = KotlinLogging.logger {}

    val id : UUID = UUID.randomUUID()

    init{
        logger.info { "new connection: $id" }
    }

    abstract suspend fun send(message: Message)
    abstract suspend fun receive() : Message
}