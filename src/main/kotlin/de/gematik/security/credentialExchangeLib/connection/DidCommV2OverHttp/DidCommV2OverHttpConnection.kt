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
import kotlin.collections.set
import kotlin.jvm.optionals.getOrNull

private val logger = KotlinLogging.logger {}

class DidCommV2OverHttpConnection private constructor(
    role: Role,
    var ownDid: URI,
    var remoteDid: URI,
    invitationId: String?
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

        fun getConnection(ownDid: URI, remoteDid: URI): DidCommV2OverHttpConnection? {
            return connections.values.firstOrNull {
                (it as? DidCommV2OverHttpConnection)?.let {
                    (it.ownDid == ownDid) && (it.remoteDid == remoteDid)
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
                            runCatching {
                                val body = call.receive<String>()
                                logger.debug { "==> POST: $body" }
                                val unpackResult = unpack(body)
                                logger.debug { "Message: ${unpackResult.res.message}" }
                                logger.debug { unpackResult.res.metadata }
                                check(unpackResult.from != null) { "'from' required to establish connection" }
                                val connection = getConnection(URI(unpackResult.to), URI(unpackResult.from))
                                if (connection != null) { // existing connection
                                    unpackResult.message.let {
                                        connection.channel.send(Json.decodeFromJsonElement(it))
                                        logger.info { "send to channel: ${Json.encodeToString(it)}" }
                                    }
                                } else { // establish new connection
                                    DidCommV2OverHttpConnection(
                                        Role.INVITER,
                                        URI(unpackResult.to),
                                        URI(unpackResult.from),
                                        unpackResult.res.message.pthid?.let { it }
                                    ).also {
                                        connections[it.id] = it
                                    }.use {
                                        it.state = ConnectionState.RELATIONSHIP_ESTABLISHED
                                        launch {
                                            handler(it)
                                        }
                                    }
                                }
                            }.onFailure {
                                call.respond(HttpStatusCode.BadRequest, it.message ?: "bad request")
                                logger.debug { "<== ${HttpStatusCode.Created}" }
                            }.onSuccess {
                                call.respond(HttpStatusCode.Created)
                                logger.debug { "<== ${HttpStatusCode.Created}" }
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

        var pthid: String? = null

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
        ) { // establish new connection
            ownUri ?: throw IllegalArgumentException("parameter 'from' required")
            DidCommV2OverHttpConnection(
                Role.INVITEE,
                ownUri,
                remoteUri,
                invitationId
            ).also {
                if (!engines.containsKey("${it.ownServiceEndpoint.host}:${it.ownServiceEndpoint.port}")) {
                    listen(it.ownServiceEndpoint) {} // start engine with empty handler - new connection are teared down
                }
                connections[it.id] = it
            }.use { connection ->
                connection.state = ConnectionState.RELATIONSHIP_ESTABLISHED
                pthid = invitationId?.toString()
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
        logger.info { "send: ${Json.encodeToString(message)}" }
        runCatching {
            val packedMsg = pack(
                body = Json.encodeToJsonElement<Message>(message) as JsonObject,
                type = "https://gematik.de/credential-exchange/v1",
                pthid = pthid,
                from = ownDid.toString(),
                to = remoteDid.toString(),
                protectSender = false
            )

            client.post(remoteServiceEndpoint.toURL()) {
                io.ktor.http.headers {
                    append(HttpHeaders.ContentType, "application/didcomm-enc-env;v2")
                }
                setBody(packedMsg.packedMessage)
            }

        }.onFailure { logger.info { "could not sent: ${it.message}" } }

    }

    @OptIn(ExperimentalCoroutinesApi::class)
    override suspend fun receive(): Message {
        val message = super.receive()
        logger.info { "receive from channel: ${Json.encodeToString(message)}" }
        return message
    }

    override fun close() {
        state = ConnectionState.RELATIONSHIP_ESTABLISHED
    }
}



