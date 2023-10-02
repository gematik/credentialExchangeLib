package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.websocket.WsConnection
import de.gematik.security.credentialExchangeLib.extensions.createUri
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class WsConnectionTests {
    @Test
    fun pingPong() {
        WsConnection.listen {
            val response = it.receive().content.get("shot")?.jsonPrimitive?.content
            assertEquals("ping", response)
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("pong")))))
        }
        runBlocking {
            WsConnection.connect {
                it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("ping")))))
                val response = it.receive().content.get("shot")?.jsonPrimitive?.content
                assertEquals("pong", response)
            }
            delay(100)
        }
        WsConnection.stopListening()
    }

    @Test
    fun pingPong2() {
        WsConnection.listen {
            // two instances: one for ping and another for pong
            var response = it.receive().content.get("shot")?.jsonPrimitive?.content?.replace("ping", "pong")
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive(response)))))
            response = it.receive().content.get("shot")?.jsonPrimitive?.content?.replace("ping", "pong")
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive(response)))))
        }
        runBlocking {
            launch {
                WsConnection.connect {
                    it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("pingA1")))))
                    assertEquals("pongA1", it.receive().content.get("shot")?.jsonPrimitive?.content)
                    println("A1")
                    delay(100)
                    it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("pingA2")))))
                    println("A2")
                    assertEquals("pongA2", it.receive().content.get("shot")?.jsonPrimitive?.content)
                }
            }
            WsConnection.connect {
                delay(50)
                it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("pingB1")))))
                assertEquals("pongB1", it.receive().content.get("shot")?.jsonPrimitive?.content)
                println("B1")
                delay(100)
                it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("pingB2")))))
                assertEquals("pongB2", it.receive().content.get("shot")?.jsonPrimitive?.content)
                println("B2")
            }
        }
        WsConnection.stopListening()
    }

    @Test
    fun pingPong2TwoListener() {
        WsConnection.listen(createUri("0.0.0.0", 1200)) {
            val response = it.receive().content.get("shot")?.jsonPrimitive?.content?.replace("ping", "pong")
            delay(100)
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive(response)))))
        }
        WsConnection.listen(createUri("0.0.0.0", 1201)) {
            val response = it.receive().content.get("shot")?.jsonPrimitive?.content?.replace("ping", "peng")
            delay(100)
            it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive(response)))))
        }
        runBlocking {
            launch {
                WsConnection.connect(createUri("0.0.0.0", 1200)) {
                    it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("ping1")))))
                    assertEquals("pong1", it.receive().content.get("shot")?.jsonPrimitive?.content)
                }
            }
            WsConnection.connect(createUri("0.0.0.0", 1201)) {
                it.send(Message(JsonObject(mapOf("shot" to JsonPrimitive("ping2")))))
                assertEquals("peng2", it.receive().content.get("shot")?.jsonPrimitive?.content)
            }
            delay(1000)
        }
        WsConnection.stopListening()
    }
}