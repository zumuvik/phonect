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

    @PublishedApi internal val gson = Gson()

    /** Encode any message into a length-prefixed frame. */
    fun encodeFrame(obj: Any): ByteArray {
        val json = gson.toJson(obj)
        val payload = json.toByteArray(Charsets.UTF_8)
        val header = ByteBuffer.allocate(4).putInt(payload.size).array()
        return header + payload
    }

    /**
     * Read one complete frame from [inputStream] and parse as [T].
     *
     * @return decoded message or null if stream closed.
     * @throws SecurityException if frame exceeds [MAX_FRAME_SIZE].
     */
    @Throws(IOException::class, SecurityException::class)
    inline fun <reified T : Any> readFrame(inputStream: InputStream): T? {
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
        return gson.fromJson(json, T::class.java)
    }

    // ------------------------------------------------------------------
    // Typed convenience methods
    // ------------------------------------------------------------------

    fun readChallenge(inputStream: InputStream): ChallengeMessage? {
        val msg = readFrame<ChallengeMessage>(inputStream) ?: return null
        if (msg.type != MSG_CHALLENGE || msg.nonce.isBlank() || msg.session_id.isBlank()) {
            return null
        }
        return msg
    }

    fun readPairAccept(inputStream: InputStream): PairAcceptMessage? {
        val msg = readFrame<PairAcceptMessage>(inputStream) ?: return null
        if (msg.type != MSG_PAIR_ACCEPT || msg.public_key_pem.isBlank()) {
            return null
        }
        return msg
    }

    fun sendResponse(outputStream: OutputStream, response: ResponseMessage) {
        outputStream.write(encodeFrame(response))
        outputStream.flush()
    }

    fun sendPairHello(outputStream: OutputStream, hello: PairHelloMessage) {
        outputStream.write(encodeFrame(hello))
        outputStream.flush()
    }

    fun readPairHello(inputStream: InputStream): PairHelloMessage? {
        val msg = readFrame<PairHelloMessage>(inputStream) ?: return null
        if (msg.type != MSG_PAIR_HELLO || msg.public_key_pem.isBlank()) {
            return null
        }
        return msg
    }

    fun sendPairAccept(outputStream: OutputStream, accept: PairAcceptMessage) {
        outputStream.write(encodeFrame(accept))
        outputStream.flush()
    }

    fun sendError(outputStream: OutputStream, sessionId: String, reason: String) {
        val error = ErrorMessage(session_id = sessionId, reason = reason)
        outputStream.write(encodeFrame(error))
        outputStream.flush()
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Read exactly [n] bytes from [inputStream], or return null on EOF. */
    @PublishedApi internal fun readExactly(inputStream: InputStream, buffer: ByteArray): ByteArray? {
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
