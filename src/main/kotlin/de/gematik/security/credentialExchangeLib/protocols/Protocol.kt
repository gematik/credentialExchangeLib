package de.gematik.security.credentialExchangeLib.protocols

import mu.KotlinLogging
import java.io.Closeable
import java.util.*

private val logger = KotlinLogging.logger {}

sealed class Protocol : Closeable {

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
        logger.info { "new context: $id" }
    }

    abstract suspend fun receive() : LdObject
    protected abstract fun connected(invitation: Invitation)
}