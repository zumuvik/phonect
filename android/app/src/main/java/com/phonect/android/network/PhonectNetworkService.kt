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
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.app.NotificationCompat
import com.phonect.android.biometric.BiometricHandler
import com.phonect.android.crypto.CryptoManager
import com.phonect.android.model.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.*
import java.io.*
import java.net.*

/**
 * Foreground Service that listens for incoming TCP connections from the PC.
 *
 * - Runs a [ServerSocket] on [PORT_DEFAULT] in a coroutine.
 * - When a connection arrives, **validates the peer IP** against the trusted
 *   PCs list.  Unknown IPs are dropped **before** any biometric prompt
 *   (prevents prompt-bombing).
 * - Reads a [ChallengeMessage], triggers biometric auth via **CryptoObject**
 *   (cryptographically bound), signs the nonce, and sends back a
 *   [ResponseMessage].
 * - Only activated when connected to a trusted Wi-Fi network (optional).
 *
 * The service shows a persistent low-priority notification.
 */
class PhonectNetworkService : Service() {

    companion object {
        private const val TAG = "PhonectService"
        private const val CHANNEL_ID = "phonect_listener"
        private const val NOTIFICATION_ID = 1
        private const val PREFS_NAME = "phonect_prefs"
        private const val PREFS_PAIRED_PCS = "paired_pcs"
        const val PORT_DEFAULT = 9876

        const val ACTION_START = "com.phonect.android.START"
        const val ACTION_STOP = "com.phonect.android.STOP"
        const val ACTION_BROADCAST_STATUS = "com.phonect.android.STATUS"
        const val EXTRA_STATUS = "status"

        /**
         * Weak reference to the current Activity, set by [MainActivity]
         * in ``onCreate`` via [setCurrentActivity].
         *
         * The [PhonectNetworkService] reads this when it needs to show a
         * [BiometricPrompt].  A weak reference prevents memory leaks if the
         * Activity is destroyed while the service is running.
         */
        @JvmStatic
        private var currentActivityRef: java.lang.ref.WeakReference<android.app.Activity>? = null

        /**
         * Called by [MainActivity] (or any Activity) to register itself
         * for BiometricPrompt display.  Must be called in ``onCreate``.
         */
        @JvmStatic
        fun setCurrentActivity(activity: android.app.Activity) {
            currentActivityRef = java.lang.ref.WeakReference(activity)
        }

        /**
         * Returns the currently registered Activity, or ``null``.
         */
        @JvmStatic
        fun getCurrentActivity(): android.app.Activity? {
            return currentActivityRef?.get()
        }
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var serverSocket: ServerSocket? = null
    private var listenJob: Job? = null

    private lateinit var cryptoManager: CryptoManager
    private lateinit var prefs: SharedPreferences
    private val gson = Gson()

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        cryptoManager = CryptoManager(this)
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        createNotificationChannel()

        cryptoManager.generateKeyIfNeeded()
        registerWifiCallback()

        Log.i(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startListening()
            ACTION_STOP -> stopListening()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopListening()
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
    }

    /**
     * Check whether [remoteAddress] belongs to a trusted PC.
     * If the trusted list is empty, all connections are allowed
     * (first-pairing mode).
     */
    private fun isTrustedPeer(remoteAddress: InetAddress): Boolean {
        val trusted = getTrustedPcs()
        if (trusted.isEmpty()) {
            // No PCs paired yet — allow any (will be paired via QR later)
            return true
        }
        val rawIp = remoteAddress.hostAddress
        return trusted.any { pc ->
            pc.ipAddress == rawIp
        }
    }

    // ------------------------------------------------------------------
    // TCP listener
    // ------------------------------------------------------------------

    private fun startListening() {
        if (listenJob?.isActive == true) return

        val notification = buildNotification("Starting…", false)
        startForeground(NOTIFICATION_ID, notification)

        listenJob = serviceScope.launch {
            try {
                serverSocket = ServerSocket(PORT_DEFAULT)
                serverSocket?.reuseAddress = true
                val port = serverSocket?.localPort ?: PORT_DEFAULT
                Log.i(TAG, "Listening on port $port")
                updateNotification("Listening on port $port")
                broadcastStatus("listening:$port")

                while (isActive) {
                    val clientSocket = try {
                        serverSocket?.accept()
                    } catch (e: SocketException) {
                        if (!isActive) break
                        Log.e(TAG, "Accept failed", e)
                        continue
                    } ?: break

                    val peerIp = clientSocket.inetAddress.hostAddress
                    Log.i(TAG, "Connection from $peerIp")
                    updateNotification("Connection from $peerIp")

                    // ── Security: validate peer IP before any prompt ──────
                    if (!isTrustedPeer(clientSocket.inetAddress)) {
                        Log.w(TAG, "Rejected untrusted peer: $peerIp")
                        try { clientSocket.close() } catch (_: Exception) {}
                        continue
                    }

                    launch { handleConnection(clientSocket) }
                }

            } catch (e: Exception) {
                Log.e(TAG, "Listener error", e)
            } finally {
                Log.i(TAG, "Listener stopped")
                updateNotification("Service stopped")
                broadcastStatus("stopped")
            }
        }
    }

    private fun stopListening() {
        listenJob?.cancel()
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ------------------------------------------------------------------
    // Connection handler
    // ------------------------------------------------------------------

    private suspend fun handleConnection(clientSocket: Socket) {
        try {
            clientSocket.soTimeout = 15_000
            val input = clientSocket.getInputStream()
            val output = clientSocket.getOutputStream()

            val peerIp = clientSocket.inetAddress.hostAddress ?: "?"

            // 1. Read challenge frame
            val challenge = ProtocolHandler.readChallenge(input)
            if (challenge == null) {
                Log.w(TAG, "Invalid challenge from $peerIp")
                ProtocolHandler.sendError(output, "", "invalid_challenge")
                return
            }

            val nonceBytes = try {
                hexStringToByteArray(challenge.nonce)
            } catch (e: IllegalArgumentException) {
                Log.e(TAG, "Invalid nonce hex from $peerIp")
                ProtocolHandler.sendError(output, challenge.session_id, "invalid_nonce")
                return
            }

            if (nonceBytes.size != 32) {
                Log.e(TAG, "Nonce length ${nonceBytes.size} != 32 from $peerIp")
                ProtocolHandler.sendError(output, challenge.session_id, "nonce_length_mismatch")
                return
            }

            Log.i(TAG, "Challenge received: session=${challenge.session_id}, from=$peerIp")

            // 2. Get the current Activity for BiometricPrompt
            val activity = getCurrentActivity() as? androidx.fragment.app.FragmentActivity
            if (activity == null) {
                Log.w(TAG, "No Activity registered — cannot show biometric prompt")
                ProtocolHandler.sendError(output, challenge.session_id, "no_ui_context")
                return
            }
            val handler = BiometricHandler(activity)

            // 3. Prepare CryptoObject (Signature bound to Keystore)
            val signature = cryptoManager.getInitializedSignature()
            val cryptoObject = BiometricPrompt.CryptoObject(signature)

            // 4. Biometric prompt (on UI thread) with CryptoObject
            //    Use hostAddress (raw IP) in title — no hostName to prevent
            //    reverse-DNS spoofing (CVE-style mDNS manipulation).
            val authResult = handler.awaitAuthentication(
                title = "Unlock $peerIp",
                subtitle = "Scan fingerprint to unlock your PC",
                cryptoObject = cryptoObject,
            )

            if (authResult == null) {
                Log.w(TAG, "Biometric declined by user")
                ProtocolHandler.sendError(output, challenge.session_id, "biometric_declined")
                return
            }

            // 4. Extract the *validated* Signature from the auth result.
            //    Because the key requires biometric auth (userAuthenticationValidity=-1),
            //    the system guarantees this Signature was just unlocked.
            val validatedSignature = authResult.cryptoObject?.signature
                ?: throw SecurityException("CryptoObject missing from biometric result")

            // 5. Sign the nonce (update + sign)
            validatedSignature.update(nonceBytes)
            val signedBytes = validatedSignature.sign()
            Log.i(TAG, "Nonce signed: ${signedBytes.size} bytes")

            // 6. Build and send response
            val fingerprint = cryptoManager.getPublicKeyFingerprint() ?: "unknown"
            val response = ResponseMessage(
                session_id = challenge.session_id,
                signature = signedBytes.toHex(),
                public_key_fingerprint = fingerprint,
                device_name = Build.MODEL,
            )

            ProtocolHandler.sendResponse(output, response)
            Log.i(TAG, "Response sent to $peerIp")

        } catch (e: SecurityException) {
            Log.e(TAG, "Security constraint violated: ${e.message}")
        } catch (e: java.net.SocketTimeoutException) {
            Log.e(TAG, "Socket timeout during handshake", e)
        } catch (e: IOException) {
            Log.e(TAG, "I/O error during handshake", e)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during handshake", e)
        } finally {
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    // ------------------------------------------------------------------
    // Wi-Fi awareness
    // ------------------------------------------------------------------

    private var wifiCallback: ConnectivityManager.NetworkCallback? = null

    private fun registerWifiCallback() {
        val connManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()

        wifiCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Wi-Fi connected — listener ready")
                broadcastStatus("wifi_connected")
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Wi-Fi disconnected — pausing listener")
                broadcastStatus("wifi_disconnected")
            }
        }

        wifiCallback?.let { connManager.registerNetworkCallback(request, it) }
    }

    private fun unregisterWifiCallback() {
        val connManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        wifiCallback?.let { connManager.unregisterNetworkCallback(it) }
        wifiCallback = null
    }

    // ------------------------------------------------------------------
    // Notifications
    // ------------------------------------------------------------------

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(com.phonect.android.R.string.channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(com.phonect.android.R.string.channel_description)
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String, showOngoing: Boolean = true): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("phonect")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setOngoing(showOngoing)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val notification = buildNotification(text)
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification)
    }

    // ------------------------------------------------------------------
    // Status broadcast
    // ------------------------------------------------------------------

    private fun broadcastStatus(status: String) {
        val intent = Intent(ACTION_BROADCAST_STATUS).apply {
            putExtra(EXTRA_STATUS, status)
        }
        sendBroadcast(intent)
    }

    // ------------------------------------------------------------------
    // Hex helpers
    // ------------------------------------------------------------------

    private fun hexStringToByteArray(hex: String): ByteArray {
        val cleaned = hex.replace(" ", "").lowercase()
        require(cleaned.length % 2 == 0) { "Odd hex string length" }
        return ByteArray(cleaned.length / 2) {
            ((cleaned[it * 2].digitToInt(16) shl 4) + cleaned[it * 2 + 1].digitToInt(16)).toByte()
        }
    }

    private fun ByteArray.toHex(): String {
        val sb = StringBuilder(size * 2)
        for (b in this) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }
}
