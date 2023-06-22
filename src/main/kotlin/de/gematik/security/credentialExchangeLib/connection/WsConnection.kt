package de.gematik.security.credentialExchangeLib.connection

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.websocket.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import io.ktor.websocket.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class WsConnection private constructor(val session: DefaultWebSocketSession) : Connection() {

    companion object : ConnectionFactory {
        val client = HttpClient(CIO) {
            install(io.ktor.client.plugins.websocket.WebSockets) {
                contentConverter = KotlinxWebsocketSerializationConverter(Json)
            }
        }

        override fun listen(wait: Boolean, connectionHandler: suspend (Connection) -> Unit): ApplicationEngine {

            val engine = embeddedServer(io.ktor.server.cio.CIO, port = 8090) {
                install(io.ktor.server.websocket.WebSockets) {
                    contentConverter = KotlinxWebsocketSerializationConverter(Json)
                }
                routing {
                    webSocket("/ws") {
                        getConnection(this).use {
                            connectionHandler(it)
                        }
                    }
                }
            }
            engine.start(wait)
            return engine
        }

        override fun connect(host: String, port: Int, wait: Boolean, connectionHandler: suspend (Connection) -> Unit) {
            runBlocking {
                if (wait) {
                    connectInternal(host, port, wait, connectionHandler)
                } else {
                    launch {
                        connectInternal(host, port, wait, connectionHandler)
                    }
                }
            }
        }

        private suspend fun connectInternal(
            host: String,
            port: Int,
            wait: Boolean,
            connectionHandler: suspend (Connection) -> Unit
        ) {
            client.webSocket(method = HttpMethod.Get, host = host, port = port, path = "/ws") {
                getConnection(this).use {
                    connectionHandler(it)
                }
            }
        }

        private fun getConnection(session: Any?): Connection {
            require(session is DefaultWebSocketSession)
            val connection = WsConnection(session)
            connections.put(connection.id, connection)
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

    override suspend fun receive(): Message {
        val message = when (session) {
            is DefaultClientWebSocketSession -> session.receiveDeserialized<Message>()
            is DefaultWebSocketServerSession -> session.receiveDeserialized<Message>()
            else -> throw IllegalStateException("wrong session type")
        }
        logger.info { "receive: ${Json.encodeToString(message)}" }
        return message
    }
}