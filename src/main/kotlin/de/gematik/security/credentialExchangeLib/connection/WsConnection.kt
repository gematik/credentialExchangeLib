package de.gematik.security.credentialExchangeLib.connection

import de.gematik.security.credentialExchangeLib.connection.WsConnection.Companion.getConnection
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.websocket.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.http.content.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import io.ktor.websocket.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.*

internal lateinit var serverPath: String
internal lateinit var serverConnectionHandler: suspend (Connection) -> Unit

class WsConnection private constructor(private val session: DefaultWebSocketSession) : Connection() {

    companion object : ConnectionFactory {
        private val client = HttpClient(CIO) {
            install(io.ktor.client.plugins.websocket.WebSockets) {
                contentConverter = KotlinxWebsocketSerializationConverter(Json)
            }
        }

        override fun listen(
            host: String,
            port: Int,
            path: String,
            connectionHandler: suspend (Connection) -> Unit
        ): ApplicationEngine {
            serverConnectionHandler = connectionHandler
            serverPath = path
            val engine = embeddedServer(io.ktor.server.cio.CIO, host = host, port = port, module = Application::module)
            engine.start()
            return engine
        }

        override suspend fun connect(
            host: String,
            port: Int,
            path: String,
            connectionHandler: suspend (Connection) -> Unit
        ) {
            client.webSocket(method = HttpMethod.Get, host = host, port = port, path = path) {
                getConnection(this).use {
                    connectionHandler(it)
                }
            }
        }

        internal fun getConnection(session: Any?): Connection {
            require(session is DefaultWebSocketSession)
            val connection = WsConnection(session)
            connections[connection.id] = connection
            return connection
        }
    }

    override fun close() {
        connections.remove(this.id)
        runBlocking {
            logger.info("close connection: $id")
            session.close(CloseReason(CloseReason.Codes.NORMAL, "Normal"))
        }
    }

    suspend fun close(reason: CloseReason) {
        connections.remove(this.id)
        logger.info("close connection: $id with reason: ${reason.message}")
        session.close(reason)
    }

    override suspend fun send(message: Message) {
        logger.info { "send: ${Json.encodeToString(message)}" }
        when (session) {
            is DefaultClientWebSocketSession -> session.sendSerialized(message)
            is DefaultWebSocketServerSession -> session.sendSerialized(message)
        }
    }

    private var isFirstReceive = true
    override suspend fun receive(): Message {
        val message = when (session) {
            is DefaultClientWebSocketSession -> kotlin.runCatching {
                session.receiveDeserialized<Message>()
            }.getOrDefault(Message("connection closed", MessageType.CLOSED))
            is DefaultWebSocketServerSession -> {
                if (isFirstReceive && session.call.parameters.contains("oob")) {
                    Message(
                        String(Base64.getDecoder().decode(session.call.parameters["oob"])),
                        MessageType.INVITATION_ACCEPT
                    )
                } else {
                    kotlin.runCatching {
                        session.receiveDeserialized<Message>()
                    }.getOrDefault(Message("connection closed", MessageType.CLOSED))
                }
            }

            else -> throw IllegalStateException("wrong session type")
        }
        isFirstReceive = false
        logger.info { "receive: ${Json.encodeToString(message)}" }
        return message
    }
}

fun Application.module() {
    install(io.ktor.server.websocket.WebSockets) {
        contentConverter = KotlinxWebsocketSerializationConverter(Json)
    }
    routing {
        staticResources("/static", "files")
        webSocket(serverPath) {
            getConnection(this).use {
                serverConnectionHandler(it)
            }
        }
        get("/") {
            call.respondRedirect("static/about.html")
        }
    }
}
