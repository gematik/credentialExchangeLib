package de.gematik.security.credentialExchangeLib.connection.websocket

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.MessageType
import de.gematik.security.credentialExchangeLib.extensions.createUri
import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.protocols.Close
import io.ktor.client.*
import io.ktor.client.plugins.websocket.*
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.http.*
import io.ktor.serialization.kotlinx.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.http.content.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import io.ktor.websocket.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import mu.KotlinLogging
import java.net.URI
import java.util.*

private val logger = KotlinLogging.logger {}

class WsConnection private constructor(val session: DefaultWebSocketSession, role : Role, invitationId: UUID?) :
    Connection(role, invitationId) {

    private lateinit var job : Job

    suspend private fun start() {
        var isCancelledOrClosed = false
        while (!isCancelledOrClosed) {
            val message = kotlin.runCatching {
                when (session) {
                    is DefaultClientWebSocketSession -> session.receiveDeserialized<Message>()
                    is DefaultWebSocketServerSession -> session.receiveDeserialized<Message>()
                    else -> throw IllegalStateException("wrong session type")
                }
            }.onFailure {
                when (it) {
                    is ClosedReceiveChannelException -> {
                        logger.debug { "connection closed by remote peer unexpectly" }
                        isCancelledOrClosed = true
                        Message(
                            json.encodeToJsonElement(Close(message = "connection closed by remote peer unexpectly")).jsonObject,
                            MessageType.CLOSE
                        )
                    }
                    is CancellationException -> {
                        logger.debug { "message receiving stopped because of: $it" }
                        isCancelledOrClosed = true
                        null
                    }
                   else -> {
                        logger.debug { "message receiving stopped because of: $it" }
                        null
                    }
                }?.let {
                    _messageFlow.emit(it)
                }
            }.getOrNull()
            message ?: continue
            logger.info { "receive: ${Json.encodeToString(message)}" }
            _messageFlow.emit(message)
        }
    }

    companion object : ConnectionFactory<WsConnection> {

        private val engines = mutableMapOf<String, ApplicationEngine>()

        private val client = HttpClient(io.ktor.client.engine.cio.CIO) {
            install(WebSockets) {
                contentConverter = KotlinxWebsocketSerializationConverter(Json)
            }
        }

        override fun listen(
            to: URI?,
            handler: suspend (WsConnection) -> Unit
        ) {
            val serviceEndPoint = to ?: createUri("0.0.0.0", 8090, "/ws")
            check(serviceEndPoint.host != null && !serviceEndPoint.host.isBlank())
            val engine = embeddedServer(CIO, host = serviceEndPoint.host, port = serviceEndPoint.port) {
                install(io.ktor.server.websocket.WebSockets) {
                    contentConverter = KotlinxWebsocketSerializationConverter(Json)
                }
                routing {
                    webSocket(serviceEndPoint.path) {// new connection
                        // first message is always 'invitation accept' - > set invitationId
                        val message = receiveDeserialized<Message>()
                        logger.info { "receive: ${Json.encodeToString(message)}" }
                        val invitationId = message.content.getOrDefault("invitationId", null)?.jsonPrimitive?.contentOrNull
                        // create connection, start connection and hand over to handler
                        WsConnection(this, Role.INVITER, invitationId?.let{UUID.fromString(it)}).also {
                            it.job = launch { it.start() }
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
            engines.put("${serviceEndPoint.host}:${serviceEndPoint.port}", engine)
        }

        override suspend fun connect(
            to: URI?,
            from: URI?,
            invitationId: UUID?,
            firstProtocolMessage: Message?,
            handler: suspend (WsConnection) -> Unit
        ) {
            val serviceEndpoint = to ?: createUri("127.0.0.1", 8090, "/ws")
            client.webSocket(
                method = HttpMethod.Get,
                host = serviceEndpoint.host,
                port = serviceEndpoint.port,
                path = serviceEndpoint.path
            ) {
                val invitationAccept = Message(
                    content = JsonObject(
                            mapOf("invitationId" to JsonPrimitive(invitationId?.toString()))
                    ),
                    MessageType.INVITATION_ACCEPT
                )
                logger.info { "send: ${Json.encodeToString(invitationAccept)}" }
                this.sendSerialized(invitationAccept)
                firstProtocolMessage?.let {
                    logger.info { "send: ${Json.encodeToString(firstProtocolMessage)}" }
                    this.sendSerialized(firstProtocolMessage)
                }
                WsConnection(this, Role.INVITEE, invitationId).also {
                    it.job = launch { it.start() }
                    connections[it.id] = it
                }.use {
                    handler(it)
                }
            }
        }

        override fun stopListening(to: URI?) {
            if (to == null) {
                engines.values.forEach { it.stop() }
                return
            }
            engines.filter {
                "${to.host ?: ""}:${to.port < 0}" == "${
                    if (to.host != null) it.key.substringBefore(":") else ""
                }:${
                    if (to.port < 0) it.key.substringAfter(":") else ""
                }"
            }.values.forEach { it.stop() }
        }

    }

    override fun close() {
        runBlocking {
            close(CloseReason(CloseReason.Codes.NORMAL, "Normal"))
        }
    }

    suspend fun close(reason: CloseReason) {
        job.cancel(CancellationException(reason.message))
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
        logger.info { "send: ${Json.encodeToString(message)}" }
        runCatching {
            when (session) {
                is DefaultClientWebSocketSession -> session.sendSerialized(message)
                is DefaultWebSocketServerSession -> session.sendSerialized(message)
            }
        }.onFailure { logger.debug {"message not send due to: $it" } }
    }

}