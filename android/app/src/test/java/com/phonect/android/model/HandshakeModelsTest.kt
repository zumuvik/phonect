package com.phonect.android.model

import com.google.gson.Gson
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Test

class HandshakeModelsTest {
    private val gson = Gson()

    @Test fun handshakeMessagesRoundTripWithCanonicalWireFieldNames() {
        assertWireSchema(
            ChallengeMessage(session_id = "session", nonce = "nonce", pc_key_fingerprint = "fingerprint", pc_signature = "signature"),
            ChallengeMessage::class.java,
            setOf("version", "type", "session_id", "nonce", "pc_key_fingerprint", "pc_signature"),
        )
        assertWireSchema(
            ResponseMessage(session_id = "session", signature = "signature", public_key_fingerprint = "fingerprint", device_name = "phone"),
            ResponseMessage::class.java,
            setOf("version", "type", "session_id", "signature", "public_key_fingerprint", "device_name"),
        )
        assertWireSchema(
            ErrorMessage(session_id = "session", reason = "reason"),
            ErrorMessage::class.java,
            setOf("version", "type", "session_id", "reason"),
        )
        assertWireSchema(
            PairHelloMessage(session_id = "session", public_key_pem = "pem", public_key_fingerprint = "fingerprint", device_name = "phone"),
            PairHelloMessage::class.java,
            setOf("version", "type", "session_id", "public_key_pem", "public_key_fingerprint", "device_name"),
        )
        assertWireSchema(
            PairAcceptMessage(session_id = "session", public_key_pem = "pem", public_key_fingerprint = "fingerprint"),
            PairAcceptMessage::class.java,
            setOf("version", "type", "session_id", "public_key_pem", "public_key_fingerprint"),
        )
    }

    private fun <T> assertWireSchema(message: T, type: Class<T>, expected: Set<String>) {
        val json = gson.toJson(message)
        assertEquals(expected, JsonParser.parseString(json).asJsonObject.keySet())
        assertEquals(message, gson.fromJson(json, type))
    }
}
