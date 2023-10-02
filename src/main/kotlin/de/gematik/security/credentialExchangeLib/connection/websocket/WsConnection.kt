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

private val logger = KotlinLogging.logger {}

class WsConnection private constructor(val session: DefaultWebSocketSession, role : Role, invitationId: String?) :
    Connection(role, invitationId) {

    private lateinit var job : Job

    suspend private fun start() {
        var isCancelledOrClosed = false
        while (!isCancelledOrClosed) {
            val message = kotlin.runCatching {
                when (session) {
                    is DefaultClientWebSocketSession -> session.receiveDeserialized<Message>().also {
                        logger.info { "receive (client): ${Json.encodeToString(it)}" }
                    }
                    is DefaultWebSocketServerSession -> session.receiveDeserialized<Message>().also {
                        logger.info { "receive (server): ${Json.encodeToString(it)}" }
                    }
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
                    channel.send(it)
                }
            }.getOrNull()
            message ?: continue
            channel.send(message)
            logger.info { "send to channel: ${Json.encodeToString(message)}" }

        }
    }

    companion object : ConnectionFactory<WsConnection> {

        private val engines = mutableMapOf<String, ApplicationEngine>()

        private val client = HttpClient(io.ktor.client.engine.cio.CIO) {
            install(WebSockets) {
                contentConverter = KotlinxWebsocketSerializationConverter(Json)
            }
        }

        override fun listen(handler: suspend (WsConnection) -> Unit) {
            listen(createUri("0.0.0.0", 8090, "/ws"), handler)
        }

        override fun listen(
            serviceEndpoint: URI,
            handler: suspend (WsConnection) -> Unit
        ) {
            check(serviceEndpoint.host != null && !serviceEndpoint.host.isBlank()) {"invalid host"}
            check(serviceEndpoint.port > 0) {"invalid port"}
            val engine = embeddedServer(CIO, host = serviceEndpoint.host, port = serviceEndpoint.port) {
                install(io.ktor.server.websocket.WebSockets) {
                    contentConverter = KotlinxWebsocketSerializationConverter(Json)
                }
                routing {
                    webSocket(serviceEndpoint.path) {// new connection
                        // first message is always 'invitation accept' - > set invitationId
                        val message = receiveDeserialized<Message>()
                        logger.info { "receive: ${Json.encodeToString(message)}" }
                        val invitationId = message.content.getOrDefault("invitationId", null)?.jsonPrimitive?.contentOrNull
                        // create connection, start connection and hand over to handler
                        WsConnection(this, Role.INVITER, invitationId?.let{it}).also {
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
            engines.put("${serviceEndpoint.host}:${serviceEndpoint.port}", engine)
        }

        override suspend fun connect(
            ownUri: URI?,
            invitationId: String?,
            firstProtocolMessage: Message?,
            handler: suspend (WsConnection) -> Unit
        ) {
            connect(createUri("127.0.0.1", 8090, "/ws"), ownUri, invitationId, firstProtocolMessage, handler)
        }

            override suspend fun connect(
            remoteUri: URI,
            ownUri: URI?,
            invitationId: String?,
            firstProtocolMessage: Message?,
            handler: suspend (WsConnection) -> Unit
        ) {
            client.webSocket(
                method = HttpMethod.Get,
                host = remoteUri.host,
                port = remoteUri.port,
                path = remoteUri.path
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

        override fun stopListening(serviceEndpoint: URI?) {
            if (serviceEndpoint == null) {
                engines.values.forEach { it.stop() }
            }else{
                val key = "${serviceEndpoint.host}:${serviceEndpoint.port}"
                engines.filter {it.key == key}.values.forEach { it.stop() }
            }
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
        runCatching {
            when (session) {
                is DefaultClientWebSocketSession -> {
                    logger.info { "send (client): ${Json.encodeToString(message)}" }
                    session.sendSerialized(message)
                }
                is DefaultWebSocketServerSession -> {
                    logger.info { "send (server): ${Json.encodeToString(message)}" }
                    session.sendSerialized(message)
                }
            }
        }.onFailure { logger.debug {"message not send because of: $it" } }
    }

}