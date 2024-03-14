/*
 * Copyright 2021-2024, gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

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
        val serviceEndpointInviter = URI.create("http://127.0.0.1:8090/didcomm")
        val serviceEndpointInvitee = URI.create("http://127.0.0.1:8091/didcomm")
        val didInviter = createPeerDID(serviceEndpoint = serviceEndpointInviter.toString())   // did of inviter transported out of band to invitee
        val didInvitee = createPeerDID(serviceEndpoint = serviceEndpointInvitee.toString())   // did of invitee used as from in connect
        // inviter creates connection after receiving invitation accept
        DidCommV2OverHttpConnection.listen(serviceEndpointInviter) {
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("ping" ))))) // inviter sends ping
            val response = it.receive()
            assertEquals(response.content.get("shot")?.jsonPrimitive?.content, "pong")
        }
        // invitee receives invitation out of band, establishes connection and waits for ping
        runBlocking {
            DidCommV2OverHttpConnection.connect(URI.create(didInviter), URI.create(didInvitee), invitationId.toString(), null) {
                val response = it.receive().content.get("shot")?.jsonPrimitive?.content
                assert(response == "ping")
                delay(100)
                it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("pong" ))))) // invitee sends pong
            }
        }
        DidCommV2OverHttpConnection.stopListening(serviceEndpointInviter)
    }
}