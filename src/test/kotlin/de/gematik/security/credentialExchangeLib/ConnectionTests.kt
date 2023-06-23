package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.connection.Message
import de.gematik.security.credentialExchangeLib.connection.WsConnection
import kotlinx.coroutines.*
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class ConnectionTests {
    @Test
    fun pingPong() {
        val engine = WsConnection.listen {
            it.send(Message("pong"))
        }
        runBlocking {
            WsConnection.connect {
                it.send(Message("ping"))
                assertEquals(Message("pong"), it.receive())
            }
        }
        engine.stop()
    }

    @Test
    fun pingPong2() {
        val engine = WsConnection.listen {
            val message = it.receive()
            delay(100)
            it.send(Message(message.content.replace("ping", "pong")))
        }
        runBlocking {
            launch {
                WsConnection.connect {
                    it.send(Message("ping1"))
                    assertEquals(Message("pong1"), it.receive())
                }
            }
            WsConnection.connect {
                it.send(Message("ping2"))
                assertEquals(Message("pong2"), it.receive())
            }
        }
        engine.stop()
    }
}