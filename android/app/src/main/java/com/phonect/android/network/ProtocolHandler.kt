package com.phonect.android.network

import com.google.gson.Gson
import com.phonect.android.model.*
import java.io.*
import java.net.Socket
import java.net.SocketException
import java.nio.ByteBuffer

/**
 * Handles the wire-format protocol: length-prefixed JSON frames
 * compatible with [phonect.protocol][src/phonect/protocol.py].
 *
 * Frame format:
 *   [4-byte big-endian payload length][UTF-8 JSON payload]
 */

object ProtocolHandler {

    private val gson = Gson()

    /** Encode a [ResponseMessage] into a length-prefixed frame. */
    fun encodeFrame(response: ResponseMessage): ByteArray {
        val json = gson.toJson(response)
        val payload = json.toByteArray(Charsets.UTF_8)
        val header = ByteBuffer.allocate(4).putInt(payload.size).array()
        return header + payload
    }

    /** Encode an [ErrorMessage] into a length-prefixed frame. */
    fun encodeError(error: ErrorMessage): ByteArray {
        val json = gson.toJson(error)
        val payload = json.toByteArray(Charsets.UTF_8)
        val header = ByteBuffer.allocate(4).putInt(payload.size).array()
        return header + payload
    }

    /**
     * Read one complete frame from [inputStream].
     *
     * @return decoded [ChallengeMessage] or null if stream closed / invalid.
     * @throws SocketException on connection reset.
     * @throws IOException on I/O errors.
     * @throws SecurityException if frame exceeds [MAX_FRAME_SIZE].
     */
    @Throws(IOException::class, SecurityException::class)
    fun readChallenge(inputStream: InputStream): ChallengeMessage? {
        // 1. Read 4-byte header
        val header = ByteArray(FRAME_HEADER_SIZE)
        readExactly(inputStream, header) ?: return null

        val payloadLength = ByteBuffer.wrap(header).getInt()

        // 2. Enforce max frame size (64 KB)
        if (payloadLength <= 0 || payloadLength > MAX_FRAME_SIZE) {
            throw SecurityException(
                "Frame payload length $payloadLength exceeds limit $MAX_FRAME_SIZE"
            )
        }

        // 3. Read payload
        val payload = ByteArray(payloadLength)
        readExactly(inputStream, payload) ?: return null

        // 4. Parse JSON
        val json = String(payload, Charsets.UTF_8)
        val msg = gson.fromJson(json, ChallengeMessage::class.java)

        // 5. Validate
        if (msg.type != MSG_CHALLENGE || msg.nonce.isBlank() || msg.session_id.isBlank()) {
            return null
        }

        return msg
    }

    /**
     * Send a [ResponseMessage] over [outputStream].
     */
    fun sendResponse(outputStream: OutputStream, response: ResponseMessage) {
        val frame = encodeFrame(response)
        outputStream.write(frame)
        outputStream.flush()
    }

    /**
     * Send an [ErrorMessage] over [outputStream].
     */
    fun sendError(outputStream: OutputStream, sessionId: String, reason: String) {
        val error = ErrorMessage(session_id = sessionId, reason = reason)
        val frame = encodeError(error)
        outputStream.write(frame)
        outputStream.flush()
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Read exactly [n] bytes from [inputStream], or return null on EOF. */
    private fun readExactly(inputStream: InputStream, buffer: ByteArray): ByteArray? {
        var offset = 0
        while (offset < buffer.size) {
            val read = inputStream.read(buffer, offset, buffer.size - offset)
            if (read == -1) {
                return null  // EOF before full frame
            }
            offset += read
        }
        return buffer
    }
}
