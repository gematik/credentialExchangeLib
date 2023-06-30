package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.connection.Message
import mu.KotlinLogging
import java.io.Closeable
import java.util.*

private val logger = KotlinLogging.logger {}

sealed class Context : Closeable {

    companion object {
        @JvmStatic
        protected val contexts = Collections.synchronizedMap(mutableMapOf<UUID, Context>())
        fun getNumberOfContexts(): Int{
            return contexts.size
        }
        fun getContext(id: UUID) : Context? {
            return contexts.get(id)
        }
    }

    val id : UUID = UUID.randomUUID()

    init{
        logger.info { "new context: $id" }
    }

    abstract suspend fun receive() : LdObject
}