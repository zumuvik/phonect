package com.phonect.android.network

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
import java.net.*
import java.nio.ByteBuffer

/**
 * Foreground Service that listens for UDP discovery broadcasts from the PC.
 *
 * - Listens on UDP port [UDP_DISCOVERY_PORT] (9875) for `PHONECT_DISCOVERY:` packets.
 * - On discovery, connects to the PC via TCP (port [PC_LISTEN_PORT]) and performs:
 *   1. **TOFU (Trust On First Use)**: sends `pair_hello` with the phone's public key,
 *      receives `pair_accept` with the PC's public key, saves PC in trusted list.
 *   2. **Challenge-response**: receives challenge, triggers biometric auth via
 *      **CryptoObject**, signs the nonce, sends response.
 * - Shows a persistent low-priority notification.
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
    private var udpSocket: DatagramSocket? = null
    private val connectingTo = mutableSetOf<String>()  // debounce: IPs we're already connecting to

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

        registerWifiCallback()
        LogManager.i(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val notification = buildNotification("Listening for PCs…", false)
                startForeground(NOTIFICATION_ID, notification)
                startDiscovery()
            }
            ACTION_STOP -> stopDiscovery()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopDiscovery()
        serviceScope.cancel()
        unregisterWifiCallback()
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
     * Find a trusted PC by IP address.
     *
     * Returns the matching [PairedPc] record, or `null` if the IP is unknown.
     * When no PCs are paired at all (first-time), returns null — caller
     * should proceed with TOFU.
     */
    private fun findTrustedPeer(remoteAddress: InetAddress): PairedPc? {
        val trusted = getTrustedPcs()
        if (trusted.isEmpty()) return null
        val rawIp = remoteAddress.hostAddress
        return trusted.firstOrNull { pc -> pc.ipAddress == rawIp }
    }

    // ------------------------------------------------------------------
    // UDP discovery listener
    // ------------------------------------------------------------------

    private fun startDiscovery() {
        if (listenJob?.isActive == true) return

        listenJob = serviceScope.launch {
            try {
                udpSocket = DatagramSocket(UDP_DISCOVERY_PORT).apply {
                    reuseAddress = true
                    broadcast = true
                    soTimeout = 5000  // 5s timeout for cancellation
                }
                LogManager.i(TAG, "UDP discovery listening on port $UDP_DISCOVERY_PORT")
                updateNotification("Listening for PCs (UDP :$UDP_DISCOVERY_PORT)")
                broadcastStatus("listening:udp:$UDP_DISCOVERY_PORT")

                val buffer = ByteArray(512)
                val packet = DatagramPacket(buffer, buffer.size)

                while (isActive) {
                    try {
                        udpSocket?.receive(packet) ?: break
                    } catch (e: SocketTimeoutException) {
                        continue  // timeout is normal — re-loop for cancellation check
                    }

                    val data = String(
                        packet.data, packet.offset, packet.length, Charsets.UTF_8
                    )
                    val pcIp = packet.address.hostAddress ?: continue

                    if (data.startsWith(DISCOVERY_PREFIX)) {
                        val parts = data.removePrefix(DISCOVERY_PREFIX).split(":")
                        val pcName = parts.getOrElse(0) { "PC" }
                        LogManager.i(TAG, "Discovery from $pcIp: $pcName")

                        // Connect to PC in a new coroutine (don't block UDP listener)
                        launch {
                            connectToPc(pcIp, PC_LISTEN_PORT, pcName)
                        }
                    }
                }
            } catch (e: Exception) {
                LogManager.e(TAG, "UDP discovery error", e)
                updateNotification("Error: ${e.message ?: "unknown"}")
                broadcastStatus("error")
            } finally {
                try { udpSocket?.close() } catch (_: Exception) {}
                LogManager.i(TAG, "UDP discovery stopped")
                updateNotification("Service stopped")
                broadcastStatus("stopped")
            }
        }
    }

    private fun stopDiscovery() {
        listenJob?.cancel()
        try { udpSocket?.close() } catch (_: Exception) {}
        udpSocket = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ------------------------------------------------------------------
    // TCP connection to PC
    // ------------------------------------------------------------------

    private suspend fun connectToPc(pcIp: String, port: Int, pcName: String) {
        // Debounce: skip if already connecting to this IP
        if (!connectingTo.add(pcIp)) return
        var socket: Socket? = null
        try {
            LogManager.i(TAG, "Connecting to $pcIp:$port ...")

            socket = Socket()
            socket.connect(InetSocketAddress(pcIp, port), 10_000)

            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            // ── Step 1: TOFU — send pair_hello ──────────────────────
            val pubKeyPem = cryptoManager.getPublicKeyPem()
            val pubKeyFp = cryptoManager.getPublicKeyFingerprint()
            if (pubKeyPem == null || pubKeyFp == null) {
                LogManager.e(TAG, "Phone key not ready — skipping handshake")
                return
            }

            val hello = PairHelloMessage(
                public_key_pem = pubKeyPem,
                public_key_fingerprint = pubKeyFp,
                device_name = Build.MODEL,
            )
            ProtocolHandler.sendPairHello(output, hello)
            LogManager.i(TAG, "PairHello sent to $pcIp")

            // ── Step 2: Receive pair_accept ─────────────────────────
            val accept = ProtocolHandler.readPairAccept(input)
            if (accept == null) {
                LogManager.w(TAG, "No PairAccept from $pcIp — aborting")
                return
            }
            LogManager.i(TAG, "PairAccept received from $pcIp")

            // Save PC in trusted list
            saveTrustedPc(
                name = pcName,
                ipAddress = pcIp,
                port = port,
                publicKeyPem = accept.public_key_pem,
                publicKeyFingerprint = accept.public_key_fingerprint,
            )

            // ── Step 3: Read challenge ──────────────────────────────
            val challenge = ProtocolHandler.readChallenge(input)
            if (challenge == null) {
                LogManager.w(TAG, "No challenge from $pcIp")
                return
            }
            LogManager.i(TAG, "Challenge received: session=${challenge.session_id}")

            val nonceBytes = try {
                hexStringToByteArray(challenge.nonce)
            } catch (e: IllegalArgumentException) {
                LogManager.e(TAG, "Invalid nonce hex from $pcIp")
                return
            }
            if (nonceBytes.size != 32) {
                LogManager.e(TAG, "Nonce length ${nonceBytes.size} != 32")
                return
            }

            // ── Step 4: Verify PC signature (mutual auth) ────────────
            val trustedPc = findTrustedPeer(InetAddress.getByName(pcIp))
            if (trustedPc != null &&
                challenge.pc_signature != null &&
                challenge.pc_key_fingerprint != null
            ) {
                val pcValid = cryptoManager.verifyPcSignature(
                    nonce = nonceBytes,
                    signature = challenge.pc_signature,
                    pcPublicKeyPem = trustedPc.publicKeyPem,
                )
                if (!pcValid) {
                    LogManager.w(TAG, "Mutual auth FAILED — PC signature invalid for $pcIp")
                    return
                }
                LogManager.i(TAG, "Mutual auth OK — PC verified")
            } else if (getTrustedPcs().isNotEmpty() && trustedPc == null) {
                LogManager.w(TAG, "Untrusted PC $pcIp — no matching trusted record")
                return
            }

            // ── Step 5: Biometric prompt ─────────────────────────────
            val activity = getCurrentActivity() as? androidx.fragment.app.FragmentActivity
            if (activity == null) {
                LogManager.w(TAG, "No Activity — cannot show biometric prompt")
                return
            }
            val handler = BiometricHandler(activity)
            val signature = cryptoManager.getInitializedSignature()
            val cryptoObject = BiometricPrompt.CryptoObject(signature)
            val authResult = handler.awaitAuthentication(
                title = "Unlock $pcName",
                subtitle = "Scan fingerprint to unlock your PC",
                cryptoObject = cryptoObject,
            )
            if (authResult == null) {
                LogManager.w(TAG, "Biometric declined by user")
                return
            }

            // ── Step 6: Sign nonce ───────────────────────────────────
            val validatedSignature = authResult.cryptoObject?.signature
                ?: throw SecurityException("CryptoObject missing from biometric result")
            validatedSignature.update(nonceBytes)
            val signedBytes = validatedSignature.sign()
            LogManager.i(TAG, "Nonce signed: ${signedBytes.size} bytes")

            // ── Step 7: Send response ────────────────────────────────
            val response = ResponseMessage(
                session_id = challenge.session_id,
                signature = signedBytes.joinToString("") { "%02x".format(it) },
                public_key_fingerprint = pubKeyFp,
                device_name = Build.MODEL,
            )
            ProtocolHandler.sendResponse(output, response)
            LogManager.i(TAG, "Response sent to $pcIp")

        } catch (e: java.net.SocketTimeoutException) {
            LogManager.e(TAG, "Socket timeout connecting to $pcIp", e)
        } catch (e: IOException) {
            LogManager.e(TAG, "I/O error with $pcIp", e)
        } catch (e: SecurityException) {
            LogManager.e(TAG, "Security constraint: ${e.message}")
        } catch (e: Exception) {
            LogManager.e(TAG, "Unexpected error with $pcIp", e)
        } finally {
            connectingTo.remove(pcIp)
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    // ------------------------------------------------------------------
    // Trusted PC persistence
    // ------------------------------------------------------------------

    private fun saveTrustedPc(
        name: String,
        ipAddress: String,
        port: Int,
        publicKeyPem: String,
        publicKeyFingerprint: String,
    ) {
        val current = getTrustedPcs().toMutableList()

        // Update existing entry or add new
        val idx = current.indexOfFirst { it.ipAddress == ipAddress }
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
        LogManager.i(TAG, "PC saved/updated: $name ($ipAddress)")
    }

    // ------------------------------------------------------------------
    // Wi-Fi awareness
    // ------------------------------------------------------------------

    private var wifiCallback: ConnectivityManager.NetworkCallback? = null

    private fun registerWifiCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addTransportType(android.net.NetworkCapabilities.TRANSPORT_WIFI)
            .build()
        wifiCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                LogManager.i(TAG, "Wi-Fi connected")
                broadcastStatus("wifi_connected")
            }
            override fun onLost(network: Network) {
                LogManager.w(TAG, "Wi-Fi disconnected")
                broadcastStatus("wifi_disconnected")
            }
        }
        cm.registerNetworkCallback(request, wifiCallback!!)
    }

    private fun unregisterWifiCallback() {
        wifiCallback?.let {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.unregisterNetworkCallback(it)
        }
        wifiCallback = null
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
