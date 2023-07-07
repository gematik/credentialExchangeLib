package de.gematik.security.credentialExchangeLib.connection

import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.protocols.Close
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.websocket.*
import io.ktor.http.*
import io.ktor.serialization.*
import io.ktor.serialization.kotlinx.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.http.content.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import io.ktor.websocket.*
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import mu.KotlinLogging
import java.util.*

internal lateinit var serverPath: String
internal lateinit var serverConnectionHandler: suspend (WsConnection) -> Unit

private val logger = KotlinLogging.logger {}

class WsConnection private constructor(private val session: DefaultWebSocketSession) : Connection() {

    companion object : ConnectionFactory<WsConnection> {
        private val client = HttpClient(CIO) {
            install(io.ktor.client.plugins.websocket.WebSockets) {
                contentConverter = KotlinxWebsocketSerializationConverter(Json)
            }
        }

        override fun listen(
            host: String,
            port: Int,
            path: String,
            handler: suspend (WsConnection) -> Unit
        ): ApplicationEngine {
            serverConnectionHandler = handler
            serverPath = path
            val engine = embeddedServer(io.ktor.server.cio.CIO, host = host, port = port) {
                install(io.ktor.server.websocket.WebSockets) {
                    contentConverter = KotlinxWebsocketSerializationConverter(Json)
                }
                routing {
                    webSocket(serverPath) {
                        WsConnection(this).also {
                            connections[it.id] = it
                        }.use {
                            serverConnectionHandler(it)
                        }
                    }
                    staticResources("/static", "files")
                    get("/") {
                        call.respondRedirect("static/about.html")
                    }

                }
            }
            engine.start()
            return engine
        }

        override suspend fun connect(
            host: String,
            port: Int,
            path: String,
            handler: suspend (WsConnection) -> Unit
        ) {
            client.webSocket(method = HttpMethod.Get, host = host, port = port, path = path) {
                WsConnection(this).also {
                    connections[it.id] = it
                }.use {
                    handler(it)
                }
            }
        }
    }

    override fun close() {
        runBlocking {
            close(CloseReason(CloseReason.Codes.NORMAL, "Normal"))
        }
    }

    suspend fun close(reason: CloseReason) {
        connections.remove(id)
        send(
            Message(
                json.encodeToJsonElement(Close(message = "connection closed normally")).jsonObject,
                MessageType.CLOSE
            )
        )
        logger.info("close connection: $id with reason: ${reason.message}")
        session.close(reason)
    }

    override suspend fun send(message: Message) {
        logger.info { "send:    ${message.type} ${Json.encodeToString(message)}" }
        runCatching {
            when (session) {
                is DefaultClientWebSocketSession -> session.sendSerialized(message)
                is DefaultWebSocketServerSession -> session.sendSerialized(message)
            }
        }.onFailure { logger.info { it.message } }
    }

    private var isFirstReceive = true
    override suspend fun receive(): Message {
        while (true) {
            val message = when (session) {
                is DefaultClientWebSocketSession -> kotlin.runCatching {
                    session.receiveDeserialized<Message>()
                }.onFailure { handleReceiveException(it)?.let { return it } }.getOrNull()

                is DefaultWebSocketServerSession -> {
                    if (isFirstReceive && session.call.parameters.contains("oob")) {
                        Message(
                            json.parseToJsonElement(
                                String(
                                    Base64.getDecoder().decode(session.call.parameters["oob"])
                                )
                            ).jsonObject,
                            MessageType.INVITATION_ACCEPT
                        )
                    } else {
                        kotlin.runCatching {
                            session.receiveDeserialized<Message>()
                        }.onFailure { handleReceiveException(it)?.let{return it} }.getOrNull()
                    }
                }

                else -> throw IllegalStateException("wrong session type")
            }
            message ?: continue
            isFirstReceive = false
            logger.info { "receive: ${message.type} -  ${Json.encodeToString(message)}" }
            return message
        }
    }

    private fun handleReceiveException(throwable: Throwable): Message? {
        return when (throwable) {
            is WebsocketDeserializeException -> {
                logger.debug { throwable.frame.frameType.name }
                null
            }

            is ClosedReceiveChannelException -> {
                logger.debug { "connection closed by remote peer unexpectly" }
                return Message(
                    json.encodeToJsonElement(Close(message = "connection closed by remote peer unexpectly")).jsonObject,
                    MessageType.CLOSE
                )
            }

            else -> {
                logger.debug { throwable.message }
                null
            }
        }
    }
}

