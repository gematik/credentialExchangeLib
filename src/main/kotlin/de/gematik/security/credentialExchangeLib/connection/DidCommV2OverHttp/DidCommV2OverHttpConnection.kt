package de.gematik.security.credentialExchangeLib.connection.DidCommV2OverHttp

import de.gematik.security.credentialExchangeLib.connection.Connection
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import mu.KotlinLogging
import java.net.URI
import java.util.*
import kotlin.collections.set
import kotlin.jvm.optionals.getOrNull

private val logger = KotlinLogging.logger {}

class DidCommV2OverHttpConnection private constructor(
    role: Role,
    var ownDid: URI,
    var remoteDid: URI,
    var remoteServiceEndpoint: URI,
    invitationId: UUID?
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

    companion object {

        private val engines = mutableMapOf<String, ApplicationEngine>()

        private val client = HttpClient(CIO)

        fun getConnection(ownId: URI, remoteId: URI): DidCommV2OverHttpConnection? {
            return connections.values.firstOrNull {
                (it as? DidCommV2OverHttpConnection)?.let {
                    (it.ownDid == ownId) && (it.remoteDid == remoteId)
                } ?: false
            } as? DidCommV2OverHttpConnection
        }

        fun getConnection(invitationId: UUID): DidCommV2OverHttpConnection? {
            return connections.values.firstOrNull {
                (it as? DidCommV2OverHttpConnection)?.let {
                    it.invitationId == invitationId
                } ?: false
            } as? DidCommV2OverHttpConnection
        }

        fun listen(to: URI?, handler: suspend (DidCommV2OverHttpConnection) -> Unit) {

            check(to != null) { "parameter 'to' required" }
            val remoteDidDoc = DIDDocResolverPeerDID.resolve(to.toString()).getOrNull()
            check(remoteDidDoc != null) { "to is not resolveable" }
            check(!remoteDidDoc.didCommServices.isEmpty()) { "remote service missing" }
            val serviceEndpoint = URI.create(remoteDidDoc.didCommServices[0].serviceEndpoint)
            check(serviceEndpoint.host != null && !serviceEndpoint.host.isBlank())
            val engine =
                embeddedServer(io.ktor.server.cio.CIO, host = serviceEndpoint.host, port = serviceEndpoint.port) {
                    routing {
                        post(serviceEndpoint.path) {
                            val body = call.receive<String>()
                            logger.debug { "==> POST: $body" }
                            val unpackResult = unpack(body)
                            logger.debug { "Message: ${unpackResult.res.message}" }
                            logger.debug { unpackResult.res.metadata }
                            check(unpackResult.from != null) { "'from' required to establish connection" }
                            val connection = getConnection(URI(unpackResult.to), URI(unpackResult.from))
                            if (connection != null) { // existing connection
                                unpackResult.message.let {
                                    connection._messageFlow.emit(Json.decodeFromString<Message>(it.toString()))
                                    logger.info { "emit to flow: ${Json.encodeToString(Json.decodeFromString<Message>(it.toString()))}" }
                                }
                            } else { // establish new connection
                                DidCommV2OverHttpConnection(
                                    Role.INVITER,
                                    URI(unpackResult.to),
                                    URI(unpackResult.from),
                                    URI.create(DIDDocResolverPeerDID.resolve(unpackResult.from).get().didCommServices[0].serviceEndpoint),
                                    unpackResult.res.message.pthid?.let{UUID.fromString(it)}
                                ).also {
                                    connections[it.id] = it
                                }.use {
                                    it.state = ConnectionState.RELATIONSHIP_ESTABLISHED
                                    launch {
                                        handler(it)
                                    }
                                }
                            }
                            call.respond(HttpStatusCode.Created)
                            logger.debug { "<== ${HttpStatusCode.Created}" }
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

        fun stopListening(to: URI?) {
            val serviceEndPoint = to ?: createUri("0.0.0.0", 8090, "/didcomm")
            check(serviceEndPoint.host != null && !serviceEndPoint.host.isBlank())
            engines.filter {
                "${serviceEndPoint.host}:${serviceEndPoint.port}" == it.key
            }.values.forEach { it.stop() }
        }

        var pthid : String? = null

        suspend fun connect(
            to: URI?,
            from: URI?,
            invitationId: UUID?,
            firstProtocolMessage: Message?,
            handler: suspend (DidCommV2OverHttpConnection) -> Unit
        ) { // establish new connection
            from ?: throw IllegalArgumentException("parameter 'from' required")
            to ?: throw IllegalArgumentException("parameter 'to' required")
            val ownDidDoc = DIDDocResolverPeerDID.resolve(from.toString()).getOrNull()
            check(ownDidDoc != null) { "from is not resolveable" }
            val remoteDidDoc = DIDDocResolverPeerDID.resolve(to.toString()).getOrNull()
            check(remoteDidDoc != null) { "to is not resolveable" }
            check(!remoteDidDoc.didCommServices.isEmpty()) { "remote service missing" }
            DidCommV2OverHttpConnection(
                Role.INVITEE,
                from,
                to,
                URI.create(remoteDidDoc.didCommServices[0].serviceEndpoint),
                invitationId ?: UUID.randomUUID()
            ).also {
                connections[it.id] = it
            }.use { connection ->
                connection.state = ConnectionState.RELATIONSHIP_ESTABLISHED
                pthid = invitationId?.toString()
                if(firstProtocolMessage!=null){
                    connection.send(firstProtocolMessage)
                }else{
                    connection.send(
                        Message(
                            JsonObject(mapOf("invitationId" to JsonPrimitive(invitationId?.toString()))),
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

        }.onFailure { logger.info {"could not sent: ${it.message}"} }

    }

    @OptIn(ExperimentalCoroutinesApi::class)
    override suspend fun receive(): Message {
        val message = super.receive()
        logger.info { "receive from flow: ${Json.encodeToString(message)}" }
        return message
    }

    override fun close() {
        state = ConnectionState.RELATIONSHIP_ESTABLISHED
    }


}



