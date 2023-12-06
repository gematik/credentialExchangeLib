package de.gematik.security.credentialExchangeLib.connection.DidCommV2OverHttp

import de.gematik.security.credentialExchangeLib.connection.Connection
import de.gematik.security.credentialExchangeLib.connection.ConnectionFactory
import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.MessageType
import de.gematik.security.credentialExchangeLib.extensions.createUri
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.http.content.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import mu.KotlinLogging
import org.didcommx.didcomm.diddoc.DIDDoc
import java.net.URI
import java.util.UUID
import kotlin.collections.set
import kotlin.jvm.optionals.getOrNull

private val logger = KotlinLogging.logger {}

class DidCommV2OverHttpConnection private constructor(
    role: Role,
    var ownDid: URI,
    var remoteDid: URI,
    invitationId: String?,
    val thid: String? = null
) : Connection(role, invitationId) {

    enum class ConnectionState {
        INITIALIZED,

        WAIT_FOR_INVITATION_RESPONSE, // inviter only
        WAIT_FOR_ROTATED_DID, // invitee only

        RELATIONSHIP_ESTABLISHED,
        WAIT_FOR_MESSAGES,
        RELATIONSHIP_CLOSED,

    }

    var state: ConnectionState = ConnectionState.INITIALIZED

    private var ownDidDoc: DIDDoc
    private val ownServiceEndpoint: URI
    private var remoteDidDoc: DIDDoc
    private val remoteServiceEndpoint: URI

    init {
        ownServiceEndpoint = DIDDocResolverPeerDID.resolve(ownDid.toString()).getOrNull().let {
            check(it != null) { "ownDid is not resolveable" }
            check(!it.didCommServices.isEmpty()) { "own service missing" }
            ownDidDoc = it
            URI.create(it.didCommServices[0].serviceEndpoint)
        }
        remoteServiceEndpoint = DIDDocResolverPeerDID.resolve(remoteDid.toString()).getOrNull().let {
            check(it != null) { "remoteDid is not resolveable" }
            check(!it.didCommServices.isEmpty()) { "remote service missing" }
            remoteDidDoc = it
            URI.create(it.didCommServices[0].serviceEndpoint)
        }
        logger.info { "new connection - ownDid: $ownDid, ownServiceEndpoint: $ownServiceEndpoint" }
        logger.info { "new connection - remoteDid: $remoteDid, remoteServiceEndpoint: $remoteServiceEndpoint" }
    }

    companion object : ConnectionFactory<DidCommV2OverHttpConnection> {

        private val engines = mutableMapOf<String, ApplicationEngine>()

        private val client = HttpClient(CIO)

        fun getConnection(
            thid: String
        ): DidCommV2OverHttpConnection? {
            return connections.values.firstOrNull {
                (it as? DidCommV2OverHttpConnection)?.let {
                    (it.thid == thid)
                } ?: false
            } as? DidCommV2OverHttpConnection
        }

        override fun listen(handler: suspend (DidCommV2OverHttpConnection) -> Unit) {
            listen(createUri("0.0.0.0", 8090, "/didcomm"), handler)
        }

        override fun listen(serviceEndpoint: URI, handler: suspend (DidCommV2OverHttpConnection) -> Unit) {
            check(serviceEndpoint.host != null && !serviceEndpoint.host.isBlank()) { "invalid host" }
            check(serviceEndpoint.port > 0) { "invalid port" }
            val engine =
                embeddedServer(io.ktor.server.cio.CIO, host = serviceEndpoint.host, port = serviceEndpoint.port) {
                    routing {
                        post(serviceEndpoint.path) {
                            // handling incoming message
                            runCatching {
                                val body = call.receive<String>()
                                logger.info { "==> POST: $body" }
                                val unpackResult = unpack(body)
                                logger.info { "Message: ${unpackResult.res.message}" }
                                logger.info { unpackResult.res.metadata }
                                check(unpackResult.from != null) { "'from' required to establish connection" }
                                val connection = unpackResult.res.message.thid?.let { getConnection(it) }
                                if (connection != null) {
                                    // message related to existing thread (connection)
                                    unpackResult.message.let {
                                        connection.channel.send(Json.decodeFromJsonElement(it))
                                        logger.debug { "send to channel: ${Json.encodeToString(it)}" }
                                    }
                                } else {
                                    // create new thread (connection)
                                    DidCommV2OverHttpConnection(
                                        Role.INVITER,
                                        URI(unpackResult.to),
                                        URI(unpackResult.from),
                                        unpackResult.res.message.pthid,
                                        unpackResult.res.message.thid
                                    ).also {
                                        connections[it.id] = it
                                    }.use {
                                        it.state = ConnectionState.RELATIONSHIP_ESTABLISHED
                                        launch {
                                            handler(it)
                                        }
                                    }
                                }
                            }.onFailure { throwable ->
                                HttpStatusCode.BadRequest.let {
                                    call.respond(it, throwable.message ?: "bad request")
                                    logger.info { "<== $it" }
                                }
                            }.onSuccess {
                                HttpStatusCode.Created.let {
                                    call.respond(it)
                                    logger.info { "<== $it" }
                                }
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

        override fun stopListening(serviceEndpoint: URI?) {
            if (serviceEndpoint == null) {
                engines.values.forEach { it.stop() }
            } else {
                val key = "${serviceEndpoint.host}:${serviceEndpoint.port}"
                engines.filter { it.key == key }.values.forEach { it.stop() }
            }
        }

        override suspend fun connect(
            ownUri: URI?,
            invitationId: String?,
            firstProtocolMessage: Message?,
            handler: suspend (DidCommV2OverHttpConnection) -> Unit
        ) {
            connect(
                URI.create(createPeerDID(serviceEndpoint = createUri("127.0.0.1", 8090, "/didcomm").toString())),
                ownUri,
                invitationId,
                firstProtocolMessage,
                handler
            )
        }

        override suspend fun connect(
            remoteUri: URI,
            ownUri: URI?,
            invitationId: String?,
            firstProtocolMessage: Message?,
            handler: suspend (DidCommV2OverHttpConnection) -> Unit
        ) { // establish new connection and thread
            ownUri ?: throw IllegalArgumentException("parameter 'from' required")
            DidCommV2OverHttpConnection(
                Role.INVITEE,
                ownUri,
                remoteUri,
                invitationId,
                UUID.randomUUID().toString()  // new thread
            ).also {
                if (!engines.containsKey("${it.ownServiceEndpoint.host}:${it.ownServiceEndpoint.port}")) {
                    listen(it.ownServiceEndpoint) {} // start engine with empty handler - new connection are teared down
                }
                connections[it.id] = it
            }.use { connection ->
                connection.state = ConnectionState.RELATIONSHIP_ESTABLISHED
                if (firstProtocolMessage != null) {
                    connection.send(firstProtocolMessage)
                } else {
                    connection.send(
                        Message(
                            JsonObject(mapOf("invitationId" to JsonPrimitive(invitationId))),
                            MessageType.INVITATION_ACCEPT
                        )
                    )
                }
                handler(connection)
            }
        }
    }

    override suspend fun send(message: Message) {
        runCatching {
            val packedMsg = pack(
                body = Json.encodeToJsonElement<Message>(message) as JsonObject,
                type = "https://gematik.de/credential-exchange/v1",
                pthid = invitationId,
                thid = thid,
                from = ownDid.toString(),
                to = remoteDid.toString(),
                protectSender = false
            )

            logger.info { "<== send: ${Json.encodeToString(message)}" }
            client.post(remoteServiceEndpoint.toURL()) {
                io.ktor.http.headers {
                    append(HttpHeaders.ContentType, "application/didcomm-enc-env;v2")
                }
                setBody(packedMsg.packedMessage)
            }

        }.onSuccess { logger.info { "==> receive: ${it.status}" } }
            .onFailure { logger.info { "could not sent: ${it.message}" } }

    }

    @OptIn(ExperimentalCoroutinesApi::class)
    override suspend fun receive(): Message {
        val message = super.receive()
        logger.debug { "receive from channel: ${Json.encodeToString(message)}" }
        return message
    }

    override fun close() {
        state = ConnectionState.RELATIONSHIP_CLOSED
    }
}



