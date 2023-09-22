package de.gematik.security.credentialExchangeLib.connection
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import mu.KotlinLogging
import java.io.Closeable
import java.util.*

private val logger = KotlinLogging.logger {}

abstract class Connection(val role: Role, val invitationId: UUID?) : Closeable {

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
        logger.info { "new connection: $id" }
    }

    protected val _messageFlow = MutableSharedFlow<Message>()
    public val messageFlow = _messageFlow.asSharedFlow()

    abstract suspend fun send(message: Message)

    open suspend fun receive() : Message{
        return messageFlow.first()
    }
}