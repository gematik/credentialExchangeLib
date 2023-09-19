package de.gematik.security.credentialExchangeLib.connection.websocket

import de.gematik.security.credentialExchangeLib.connection.*
import de.gematik.security.credentialExchangeLib.extensions.createUri
import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.protocols.Close
import io.ktor.client.*
import io.ktor.client.plugins.websocket.*
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.http.*
import io.ktor.serialization.*
import io.ktor.serialization.kotlinx.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
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

private val logger = KotlinLogging.logger {}

class WsConnection private constructor(val session: DefaultWebSocketSession) : Connection() {
    companion object : ConnectionFactory<WsConnection> {

        private val engines = mutableMapOf<String, ApplicationEngine>()

        private val client = HttpClient(io.ktor.client.engine.cio.CIO) {
            install(WebSockets) {
                contentConverter = KotlinxWebsocketSerializationConverter(Json)
            }
        }

        override fun listen(
            connectionArgs: ConnectionArgs?,
            handler: suspend (WsConnection) -> Unit
        ) {
            val args = connectionArgs?:WsConnectionArgs()
            check(args is WsConnectionArgs)
            check(args.endpoint.host!=null && !args.endpoint.host.isBlank())
            val engine = embeddedServer(CIO, host = args.endpoint.host, port = args.endpoint.port) {
                install(io.ktor.server.websocket.WebSockets) {
                    contentConverter = KotlinxWebsocketSerializationConverter(Json)
                }
                routing {
                    webSocket(args.endpoint.path) {
                        WsConnection(this).also {
                            connections[it.id] = it
                        }.use {
                            handler(it)
                        }
                    }
                    staticResources("/static", "files")
                    get("/") {
                        call.respondRedirect("static/about.html")
                    }

                }
            }
            engine.start()
            engines.put("${args.endpoint.host}:${args.endpoint.port}", engine)
        }

        override suspend fun connect(
            connectionArgs: ConnectionArgs?,
            handler: suspend (WsConnection) -> Unit
        ) {
            val args = connectionArgs?:WsConnectionArgs(createUri("127.0.0.1", 8090, "/ws"))
            check(args is WsConnectionArgs)
            client.webSocket(method = HttpMethod.Get, host = args.endpoint.host, port = args.endpoint.port, path = args.endpoint.path?.let{"$it${args.endpoint.query?.let{"?$it"}?:""}"}) {
                WsConnection(this).also {
                    connections[it.id] = it
                }.use {
                    handler(it)
                }
            }
        }

        override fun stopListening(connectionArgs: ConnectionArgs?) {
            val args = connectionArgs ?: WsConnectionArgs()
            check(args is WsConnectionArgs)
            check(args.endpoint.host!=null && !args.endpoint.host.isBlank())
            engines.filter {
                "${args.endpoint.host}:${args.endpoint.port}" == it.key
            }.values.forEach { it.stop() }
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
                        }.onFailure { handleReceiveException(it)?.let { return it } }.getOrNull()
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