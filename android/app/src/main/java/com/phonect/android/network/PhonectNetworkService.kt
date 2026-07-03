package com.phonect.android.network

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.IBinder
import androidx.biometric.BiometricPrompt
import androidx.core.app.NotificationCompat
import com.phonect.android.biometric.BiometricHandler
import com.phonect.android.crypto.CryptoManager
import com.phonect.android.logging.LogManager
import com.phonect.android.model.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.*
import java.io.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.UUID
import java.util.Collections

/**
 * Foreground Service that listens for Wi-Fi UDP discovery from the PC.
 *
 * - Listens for PHONECT_DISCOVERY UDP packets and connects back via TCP.
 * - When the PC is discovered (after waking from sleep), performs TOFU
 *   (Trust On First Use) and challenge-response authentication.
 * - On successful signature, the unlock daemon on the PC side unlocks
 *   the session — this service only provides the signed assertion.
 */
class PhonectNetworkService : Service() {

    companion object {
        private const val TAG = "PhonectService"
        private const val CHANNEL_ID = "phonect_listener"
        private const val NOTIFICATION_ID = 1
        private const val PREFS_NAME = "phonect_prefs"
        private const val PREFS_PAIRED_PCS = "paired_pcs"

        const val ACTION_START = "com.phonect.android.START"
        const val ACTION_STOP = "com.phonect.android.STOP"
        const val ACTION_BROADCAST_STATUS = "com.phonect.android.STATUS"
        const val EXTRA_STATUS = "status"

        @JvmStatic
        private var currentActivityRef: java.lang.ref.WeakReference<android.app.Activity>? = null

        @JvmStatic
        fun setCurrentActivity(activity: android.app.Activity) {
            currentActivityRef = java.lang.ref.WeakReference(activity)
        }

        @JvmStatic
        fun getCurrentActivity(): android.app.Activity? {
            return currentActivityRef?.get()
        }
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var listenJob: Job? = null
    private var discoverySocket: DatagramSocket? = null
    private val inFlightConnections = Collections.synchronizedSet(mutableSetOf<String>())

    private lateinit var cryptoManager: CryptoManager
    private lateinit var prefs: SharedPreferences
    private val gson = Gson()

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        LogManager.init(this)
        cryptoManager = CryptoManager(this)
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        createNotificationChannel()

        serviceScope.launch {
            cryptoManager.generateKeyIfNeeded()
            LogManager.i(TAG, "Key generation completed")
        }

        LogManager.i(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val notification = buildNotification("Listening for PC via Wi-Fi…", false)
                startForeground(NOTIFICATION_ID, notification)
                startWifiListener()
            }
            ACTION_STOP -> stopWifiListener()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopWifiListener()
        serviceScope.cancel()
        super.onDestroy()
    }

    // ------------------------------------------------------------------
    // Trusted PCs management
    // ------------------------------------------------------------------

    /** Returns the list of currently paired PCs from SharedPreferences. */
    fun getTrustedPcs(): List<PairedPc> {
        val json = prefs.getString(PREFS_PAIRED_PCS, "[]") ?: "[]"
        val type = object : TypeToken<List<PairedPc>>() {}.type
        return gson.fromJson(json, type) ?: emptyList()
    }

    /** Persist the paired PCs list. */
    fun setTrustedPcs(pcs: List<PairedPc>) {
        prefs.edit().putString(PREFS_PAIRED_PCS, gson.toJson(pcs)).apply()
        LogManager.i(TAG, "Trusted PCs updated: ${pcs.size} device(s)")
    }

    /**
     * Find a trusted PC by its public key fingerprint.
     *
     * Returns the matching [PairedPc] record, or `null` if unknown.
     * When no PCs are paired at all (first-time), returns null — caller
     * should proceed with TOFU.
     */
    private fun findTrustedPeerByFingerprint(fingerprint: String): PairedPc? {
        val trusted = getTrustedPcs()
        if (trusted.isEmpty()) return null
        return trusted.firstOrNull { pc -> pc.publicKeyFingerprint == fingerprint }
    }

    // ------------------------------------------------------------------
    // Wi-Fi discovery listener
    // ------------------------------------------------------------------

    private fun startWifiListener() {
        if (listenJob?.isActive == true) return

        listenJob = serviceScope.launch {
            try {
                discoverySocket = DatagramSocket(UDP_DISCOVERY_PORT, InetAddress.getByName("0.0.0.0")).apply {
                    broadcast = true
                    soTimeout = 1000
                }
                LogManager.i(TAG, "UDP discovery listening on $UDP_DISCOVERY_PORT")
                updateNotification("Listening for PC via Wi-Fi")
                broadcastStatus("listening:$UDP_DISCOVERY_PORT")

                while (isActive) {
                    try {
                        val buffer = ByteArray(1024)
                        val packet = DatagramPacket(buffer, buffer.size)
                        discoverySocket?.receive(packet)
                        val payload = String(packet.data, 0, packet.length, Charsets.UTF_8).trim()
                        val discovery = parseDiscovery(payload) ?: continue
                        val sourceIp = packet.address.hostAddress ?: continue
                        val key = "${sourceIp}:${discovery.port}:${discovery.fp16}"
                        if (!inFlightConnections.add(key)) {
                            LogManager.d(TAG, "Discovery already in-flight for $key")
                            continue
                        }
                        LogManager.i(TAG, "Discovery from ${discovery.pcName} at $sourceIp:${discovery.port}")
                        launch {
                            try {
                                connectAndHandleTcp(packet.address, discovery.port, discovery.pcName, discovery.fp16)
                            } finally {
                                inFlightConnections.remove(key)
                            }
                        }
                    } catch (_: SocketTimeoutException) {
                        // Periodically wake so coroutine cancellation is observed.
                    } catch (e: IOException) {
                        if (isActive) {
                            LogManager.e(TAG, "UDP discovery error", e)
                        }
                    }
                }
            } catch (e: IOException) {
                LogManager.e(TAG, "Wi-Fi listener error", e)
                updateNotification("Error: ${e.message ?: "unknown"}")
                broadcastStatus("error")
            } finally {
                try { discoverySocket?.close() } catch (_: Exception) {}
                LogManager.i(TAG, "Wi-Fi listener stopped")
                updateNotification("Service stopped")
                broadcastStatus("stopped")
            }
        }
    }

    private fun stopWifiListener() {
        listenJob?.cancel()
        try { discoverySocket?.close() } catch (_: Exception) {}
        discoverySocket = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ------------------------------------------------------------------
    // TCP connection handler
    // ------------------------------------------------------------------

    private data class Discovery(val pcName: String, val fp16: String, val port: Int)

    private fun parseDiscovery(payload: String): Discovery? {
        val parts = payload.split(":")
        if (parts.size != 4 || parts[0] != DISCOVERY_PREFIX) return null
        val port = parts[3].toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return Discovery(parts[1], parts[2], port)
    }

    private suspend fun connectAndHandleTcp(address: InetAddress, port: Int, discoveredName: String, discoveredFp16: String) {
        withContext(Dispatchers.IO) {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(address, port), 5_000)
                socket.soTimeout = 30_000
                handleTcpConnection(socket, discoveredName, discoveredFp16, port)
            }
        }
    }

    private suspend fun handleTcpConnection(socket: Socket, discoveredName: String, discoveredFp16: String, port: Int) {
        var input: InputStream? = null
        var output: OutputStream? = null
        try {
            input = socket.inputStream
            output = socket.outputStream

            // ── Step 1: Send pair_hello with phone's public key ──
            val pubKeyPem = cryptoManager.getPublicKeyPem()
            val pubKeyFp = cryptoManager.getPublicKeyFingerprint()
            if (pubKeyPem == null || pubKeyFp == null) {
                LogManager.e(TAG, "Phone key not ready — skipping handshake")
                return
            }

            val sessionId = UUID.randomUUID().toString()
            val hello = PairHelloMessage(
                session_id = sessionId,
                public_key_pem = pubKeyPem,
                public_key_fingerprint = pubKeyFp,
                device_name = Build.MODEL,
            )
            ProtocolHandler.sendPairHello(output, hello)
            LogManager.i(TAG, "PairHello sent to PC")

            // ── Step 2: Read pair_accept with PC public key ─────────
            val accept = ProtocolHandler.readPairAccept(input)
            if (accept == null) {
                LogManager.w(TAG, "No PairAccept from PC — aborting")
                return
            }
            val pcPem = accept.public_key_pem
            val pcFp = accept.public_key_fingerprint
            val pcName = discoveredName.ifBlank { "PC" }
            val pcIp = socket.inetAddress.hostAddress ?: ""
            val pemFp = cryptoManager.fingerprintPublicKeyPem(pcPem)
            if (pemFp == null || pemFp != pcFp) {
                LogManager.w(TAG, "PairAccept fingerprint does not match PC public key PEM")
                return
            }
            if (!pcFp.startsWith(discoveredFp16, ignoreCase = true)) {
                LogManager.w(TAG, "Discovery fingerprint prefix mismatch for $pcName")
                return
            }

            // ── Step 3: Trust policy; defer TOFU persistence until proof ─
            val trustedPcs = getTrustedPcs()
            var trustedPc = findTrustedPeerByFingerprint(pcFp)
            val isNewTofu = trustedPc == null && trustedPcs.isEmpty()
            if (trustedPc != null && trustedPc.publicKeyPem != pcPem) {
                LogManager.w(TAG, "Pinned PC mismatch for ${trustedPc.name}")
                return
            }
            if (trustedPc == null) {
                if (trustedPcs.isNotEmpty()) {
                    LogManager.w(TAG, "Unknown PC $pcName (${pcFp.take(16)}…) rejected; trusted PCs already exist")
                    return
                }
                LogManager.i(TAG, "TOFU candidate PC $pcName (${pcFp.take(16)}…) will be saved after proof")
            } else {
                LogManager.d(TAG, "PC already known: ${pcFp.take(16)}…")
            }

            // ── Step 4: Read challenge ─────────────────────────────
            val challenge = ProtocolHandler.readChallenge(input)
            if (challenge == null) {
                LogManager.w(TAG, "No challenge from PC")
                return
            }
            LogManager.i(TAG, "Challenge received: session=${challenge.session_id}")

            val nonceBytes = try {
                hexStringToByteArray(challenge.nonce)
            } catch (e: IllegalArgumentException) {
                LogManager.e(TAG, "Invalid nonce hex")
                return
            }
            if (nonceBytes.size != 32) {
                LogManager.e(TAG, "Nonce length ${nonceBytes.size} != 32")
                return
            }

            // ── Step 5: Verify PC signature (mutual auth) ────────────
            if (challenge.pc_signature == null || challenge.pc_key_fingerprint != pcFp) {
                LogManager.w(TAG, "Mutual auth missing or fingerprint mismatch for $pcName")
                return
            }
            val pcValid = cryptoManager.verifyPcSignature(
                nonce = nonceBytes,
                signature = challenge.pc_signature,
                pcPublicKeyPem = trustedPc?.publicKeyPem ?: pcPem,
            )
            if (!pcValid) {
                LogManager.w(TAG, "Mutual auth FAILED — PC signature invalid for $pcName")
                return
            }
            if (isNewTofu) {
                trustedPc = saveTrustedPc(pcName, pcIp, port = port, publicKeyPem = pcPem, publicKeyFingerprint = pcFp)
                LogManager.i(TAG, "TOFU pairing saved for PC $pcName (${pcFp.take(16)}…)")
            } else if (trustedPc != null && (trustedPc.ipAddress != pcIp || trustedPc.port != port)) {
                trustedPc = saveTrustedPc(trustedPc.name, pcIp, port = port, publicKeyPem = trustedPc.publicKeyPem, publicKeyFingerprint = trustedPc.publicKeyFingerprint)
            }
            LogManager.i(TAG, "Mutual auth OK — PC verified")

            // ── Step 6: Biometric prompt ─────────────────────────────
            val activity = getCurrentActivity() as? androidx.fragment.app.FragmentActivity
            if (activity == null) {
                LogManager.w(TAG, "No Activity — cannot show biometric prompt")
                return
            }
            val handler = BiometricHandler(activity)
            val signature = cryptoManager.getInitializedSignature()
            val cryptoObject = BiometricPrompt.CryptoObject(signature)
            val authResult = handler.awaitAuthentication(
                title = "Unlock ${trustedPc?.name ?: pcName}",
                subtitle = "Scan fingerprint to unlock your PC",
                cryptoObject = cryptoObject,
            )
            if (authResult == null) {
                LogManager.w(TAG, "Biometric declined by user")
                return
            }

            // ── Step 7: Sign nonce ───────────────────────────────────
            val validatedSignature = authResult.cryptoObject?.signature
                ?: throw SecurityException("CryptoObject missing from biometric result")
            validatedSignature.update(nonceBytes)
            val signedBytes = validatedSignature.sign()
            LogManager.i(TAG, "Nonce signed: ${signedBytes.size} bytes")

            // ── Step 8: Send response ────────────────────────────────
            val response = ResponseMessage(
                session_id = challenge.session_id,
                signature = signedBytes.joinToString("") { "%02x".format(it) },
                public_key_fingerprint = pubKeyFp,
                device_name = Build.MODEL,
            )
            ProtocolHandler.sendResponse(output, response)
            LogManager.i(TAG, "Response sent to PC")

        } catch (e: java.io.IOException) {
            LogManager.e(TAG, "I/O error during TCP handshake", e)
        } catch (e: SecurityException) {
            LogManager.e(TAG, "Security constraint: ${e.message}")
        } catch (e: Exception) {
            LogManager.e(TAG, "Unexpected error during TCP handshake", e)
        } finally {
            try {
                input?.close()
                output?.close()
            } catch (_: Exception) {}
            LogManager.i(TAG, "TCP connection closed")
        }
    }

    // ------------------------------------------------------------------
    // Trusted PC persistence (keyed by fingerprint)
    // ------------------------------------------------------------------

    private fun saveTrustedPc(
        name: String,
        ipAddress: String,
        port: Int,
        publicKeyPem: String,
        publicKeyFingerprint: String,
    ): PairedPc {
        val current = getTrustedPcs().toMutableList()

        val idx = current.indexOfFirst { it.publicKeyFingerprint == publicKeyFingerprint }
        val pc = PairedPc(
            name = name,
            hostname = name,
            ipAddress = ipAddress,
            port = port,
            publicKeyPem = publicKeyPem,
            publicKeyFingerprint = publicKeyFingerprint,
        )
        if (idx >= 0) {
            current[idx] = pc
        } else {
            current.add(pc)
        }
        setTrustedPcs(current)
        LogManager.i(TAG, "PC saved/updated: $name ($publicKeyFingerprint)")
        return pc
    }

    // ------------------------------------------------------------------
    // Notifications
    // ------------------------------------------------------------------

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Phonect Service",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Phonect P2P unlock daemon notification"
        }
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String, persistent: Boolean): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Phonect")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setOngoing(persistent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val notification = buildNotification(text, persistent = true)
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, notification)
    }

    private fun broadcastStatus(status: String) {
        val intent = Intent(ACTION_BROADCAST_STATUS).putExtra(EXTRA_STATUS, status)
        sendBroadcast(intent)
    }
}

/** Convert a hex string to a ByteArray. */
private fun hexStringToByteArray(hex: String): ByteArray {
    val len = hex.length
    require(len % 2 == 0) { "Hex string must have even length" }
    return ByteArray(len / 2) {
        hex.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}
