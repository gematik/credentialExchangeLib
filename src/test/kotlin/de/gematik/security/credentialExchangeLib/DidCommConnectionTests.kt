package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.connection.DidCommV2OverHttp.DidCommV2OverHttpConnection
import de.gematik.security.credentialExchangeLib.connection.DidCommV2OverHttp.createPeerDID
import de.gematik.security.credentialExchangeLib.connection.Message
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import java.net.URI
import java.util.*
import kotlin.test.assertEquals

class DidCommConnectionTests {
    @Test
    fun pingPong() {
        val invitationId = UUID.randomUUID()
        val serviceEndpoint = URI.create("http://127.0.0.1:8090/didcomm")
        val didInviter = createPeerDID(serviceEndpoint = serviceEndpoint.toString())   // did of inviter transported out of band to invitee
        val didInvitee = createPeerDID(serviceEndpoint = serviceEndpoint.toString())   // did of invitee used as from in connect
        // inviter creates connection after receiving invitation accept
        DidCommV2OverHttpConnection.listen(URI.create(didInviter)) {
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("ping" ))))) // inviter sends ping
            val response = it.receive()
            assertEquals(response.content.get("shot")?.jsonPrimitive?.content, "pong")
        }
        // invitee receives invitation out of band and establishes connection
        runBlocking {
            DidCommV2OverHttpConnection.connect(URI.create(didInviter), URI.create(didInvitee), null, null) {
                val response = it.receive().content.get("shot")?.jsonPrimitive?.content
                assert(response == "ping")
                delay(100)
                it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("pong" ))))) // invitee sends pong
            }
        }
        DidCommV2OverHttpConnection.stopListening(serviceEndpoint)
    }
}