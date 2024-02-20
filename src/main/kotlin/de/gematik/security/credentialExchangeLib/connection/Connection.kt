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