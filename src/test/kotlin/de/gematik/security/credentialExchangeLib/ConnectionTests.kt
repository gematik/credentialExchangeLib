package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.WsConnection
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class ConnectionTests {
    @Test
    fun pingPong() {
        val engine = WsConnection.listen {
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("pong" )))))
        }
        runBlocking {
            WsConnection.connect {
                it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("ping" )))))
                assertEquals("pong", it.receive().content.get("shot")?.jsonPrimitive?.content)
            }
        }
        engine.stop()
    }

    @Test
    fun pingPong2() {
        val engine = WsConnection.listen {
            val response = it.receive().content.get("shot")?.jsonPrimitive?.content?.replace("ping", "pong")
            delay(100)
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive(response)))))
        }
        runBlocking {
            launch {
                WsConnection.connect {
                    it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("ping1" )))))
                    assertEquals("pong1", it.receive().content.get("shot")?.jsonPrimitive?.content)
                }
            }
            WsConnection.connect {
                it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("ping2" )))))
                assertEquals("pong2", it.receive().content.get("shot")?.jsonPrimitive?.content)
            }
        }
        engine.stop()
    }
}