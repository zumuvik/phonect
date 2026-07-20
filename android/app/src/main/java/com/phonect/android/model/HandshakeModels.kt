package com.phonect.android.model

import com.google.gson.annotations.SerializedName

/**
 * Wire-format messages — mirrors phonect.protocol on the Python side.
 *
 * Messages are JSON-encoded, length-prefixed frames over Wi-Fi/TCP.
 */

const val PROTOCOL_VERSION = 1
const val FRAME_HEADER_SIZE = 4   // uint32 big-endian
const val MAX_FRAME_SIZE = 65_536 // 64 KB safety limit

// Wi-Fi discovery constants (must match Python discovery payload)
const val UDP_DISCOVERY_PORT = 9875
const val PC_LISTEN_PORT = 9876
const val DISCOVERY_PREFIX = "PHONECT_DISCOVERY"

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
    @SerializedName("version") val version: Int = PROTOCOL_VERSION,
    @SerializedName("type") val type: String = MSG_CHALLENGE,
    @SerializedName("session_id") val session_id: String = "",
    @SerializedName("nonce") val nonce: String = "",                       // hex-encoded 32 bytes
    @SerializedName("pc_key_fingerprint") val pc_key_fingerprint: String? = null, // mutual auth
    @SerializedName("pc_signature") val pc_signature: String? = null,       // mutual auth
)

/** Outgoing signed response from phone. */
data class ResponseMessage(
    @SerializedName("version") val version: Int = PROTOCOL_VERSION,
    @SerializedName("type") val type: String = MSG_RESPONSE,
    @SerializedName("session_id") val session_id: String = "",
    @SerializedName("signature") val signature: String = "",                    // hex-encoded RSA-4096 PSS/SHA-512 sig
    @SerializedName("public_key_fingerprint") val public_key_fingerprint: String = "",
    @SerializedName("device_name") val device_name: String = "android-phone",
)

/** Error message (either direction). */
data class ErrorMessage(
    @SerializedName("version") val version: Int = PROTOCOL_VERSION,
    @SerializedName("type") val type: String = MSG_ERROR,
    @SerializedName("session_id") val session_id: String = "",
    @SerializedName("reason") val reason: String = "",
)

/**
 * First message from phone after TCP connect.
 *
 * Carries the sender's RSA public key so the peer can store it during
 * pairing (Trust On First Use).
 */
data class PairHelloMessage(
    @SerializedName("version") val version: Int = PROTOCOL_VERSION,
    @SerializedName("type") val type: String = MSG_PAIR_HELLO,
    @SerializedName("session_id") val session_id: String = "",
    @SerializedName("public_key_pem") val public_key_pem: String = "",
    @SerializedName("public_key_fingerprint") val public_key_fingerprint: String = "",
    @SerializedName("device_name") val device_name: String = "",
)

/**
 * Response to [PairHelloMessage].
 *
 * Carries the sender's RSA public key so the peer can store it.
 */
data class PairAcceptMessage(
    @SerializedName("version") val version: Int = PROTOCOL_VERSION,
    @SerializedName("type") val type: String = MSG_PAIR_ACCEPT,
    @SerializedName("session_id") val session_id: String = "",
    @SerializedName("public_key_pem") val public_key_pem: String = "",
    @SerializedName("public_key_fingerprint") val public_key_fingerprint: String = "",
)

/** Paired PC record — persisted in shared preferences. */
data class PairedPc(
    val name: String,
    val hostname: String,
    val ipAddress: String = "",
    val port: Int = PC_LISTEN_PORT,
    val publicKeyPem: String,
    val publicKeyFingerprint: String,
)
