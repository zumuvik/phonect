package com.phonect.android.model

import android.os.Build

/**
 * Wire-format messages — mirrors phonect.protocol on the Python side.
 *
 * Messages are JSON-encoded, length-prefixed frames over Bluetooth RFCOMM.
 */

const val PROTOCOL_VERSION = 1
const val FRAME_HEADER_SIZE = 4   // uint32 big-endian
const val MAX_FRAME_SIZE = 65_536 // 64 KB safety limit

// Message types (must match Python phonect.protocol)
const val MSG_CHALLENGE = "challenge"
const val MSG_RESPONSE = "response"
const val MSG_ERROR = "error"
const val MSG_PAIR_HELLO = "pair_hello"
const val MSG_PAIR_ACCEPT = "pair_accept"

// ---------------------------------------------------------------------------
// Kotlin data classes (serialised with Gson)
// ---------------------------------------------------------------------------

/** Incoming challenge from PC. */
data class ChallengeMessage(
    val version: Int = PROTOCOL_VERSION,
    val type: String = MSG_CHALLENGE,
    val session_id: String = "",
    val nonce: String = "",                       // hex-encoded 32 bytes
    val pc_key_fingerprint: String? = null,        // mutual auth
    val pc_signature: String? = null,              // mutual auth
)

/** Outgoing signed response from phone. */
data class ResponseMessage(
    val version: Int = PROTOCOL_VERSION,
    val type: String = MSG_RESPONSE,
    val session_id: String = "",
    val signature: String = "",                    // hex-encoded RSA-4096 PSS/SHA-512 sig
    val public_key_fingerprint: String = "",
    val device_name: String = "android-phone",
)

/** Error message (either direction). */
data class ErrorMessage(
    val version: Int = PROTOCOL_VERSION,
    val type: String = MSG_ERROR,
    val session_id: String = "",
    val reason: String = "",
)

/**
 * First message from PC after Bluetooth RFCOMM connect.
 *
 * Carries the PC's RSA public key so the phone can store it
 * (Trust On First Use).
 */
data class PairHelloMessage(
    val version: Int = PROTOCOL_VERSION,
    val type: String = MSG_PAIR_HELLO,
    val session_id: String = "",
    val public_key_pem: String = "",
    val public_key_fingerprint: String = "",
    val device_name: String = "",
)

/**
 * Phone's response to [PairHelloMessage].
 *
 * Carries the phone's RSA public key so the PC can store it.
 */
data class PairAcceptMessage(
    val version: Int = PROTOCOL_VERSION,
    val type: String = MSG_PAIR_ACCEPT,
    val session_id: String = "",
    val public_key_pem: String = "",
    val public_key_fingerprint: String = "",
)

/** Paired PC record — persisted in shared preferences. */
data class PairedPc(
    val name: String,
    val hostname: String,
    val ipAddress: String = "",          // Not used with Bluetooth
    val port: Int = 0,                   // Not used with Bluetooth
    val publicKeyPem: String,
    val publicKeyFingerprint: String,
)
