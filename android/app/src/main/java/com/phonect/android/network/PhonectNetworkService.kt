package com.phonect.android.network

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.phonect.android.biometric.BiometricHandler
import com.phonect.android.crypto.CryptoManager
import com.phonect.android.model.*
import kotlinx.coroutines.*
import java.io.*
import java.net.*

/**
 * Foreground Service that listens for incoming TCP connections from the PC.
 *
 * - Runs a [ServerSocket] on [PORT_DEFAULT] in a coroutine.
 * - When a connection arrives, reads a [ChallengeMessage], triggers
 *   biometric auth, signs the nonce, and sends back a [ResponseMessage].
 * - Only activated when connected to a trusted Wi-Fi network (optional).
 *
 * The service shows a persistent low-priority notification.
 */
class PhonectNetworkService : Service() {

    companion object {
        private const val TAG = "PhonectService"
        private const val CHANNEL_ID = "phonect_listener"
        private const val NOTIFICATION_ID = 1
        const val PORT_DEFAULT = 9876

        /** Intent actions */
        const val ACTION_START = "com.phonect.android.START"
        const val ACTION_STOP = "com.phonect.android.STOP"
        const val ACTION_BROADCAST_STATUS = "com.phonect.android.STATUS"
        const val EXTRA_STATUS = "status"
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var serverSocket: ServerSocket? = null
    private var listenJob: Job? = null

    private lateinit var cryptoManager: CryptoManager
    private lateinit var biometricHandler: BiometricHandler
    private var currentActivityRef: java.lang.ref.WeakReference<android.app.Activity>? = null

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        cryptoManager = CryptoManager(this)
        createNotificationChannel()

        // Ensure the Keystore key exists (generated once)
        cryptoManager.generateKeyIfNeeded()

        // Monitor Wi-Fi connectivity
        registerWifiCallback()

        Log.i(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startListening()
            ACTION_STOP -> stopListening()
        }
        return START_STICKY  // restart if killed
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopListening()
        serviceScope.cancel()
        unregisterWifiCallback()
        super.onDestroy()
    }

    // ------------------------------------------------------------------
    // Public API (called from Activity)
    // ------------------------------------------------------------------

    /** Set a reference to the current Activity for BiometricPrompt. */
    fun setCurrentActivity(activity: android.app.Activity) {
        currentActivityRef = java.lang.ref.WeakReference(activity)
        if (activity is androidx.fragment.app.FragmentActivity) {
            biometricHandler = BiometricHandler(activity)
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

                    Log.i(TAG, "Connection from ${clientSocket.inetAddress.hostAddress}")
                    updateNotification("Connection from ${clientSocket.inetAddress.hostAddress}")

                    // Handle each connection in a new coroutine
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
            clientSocket.soTimeout = 15_000  // 15s timeout for I/O
            val input = clientSocket.getInputStream()
            val output = clientSocket.getOutputStream()

            // 1. Read challenge frame
            val challenge = ProtocolHandler.readChallenge(input)
            if (challenge == null) {
                Log.w(TAG, "Invalid challenge from ${clientSocket.inetAddress}")
                ProtocolHandler.sendError(output, "", "invalid_challenge")
                return
            }

            val nonceBytes = try {
                hexStringToByteArray(challenge.nonce)
            } catch (e: IllegalArgumentException) {
                Log.e(TAG, "Invalid nonce hex")
                ProtocolHandler.sendError(output, challenge.session_id, "invalid_nonce")
                return
            }

            if (nonceBytes.size != 32) {
                Log.e(TAG, "Nonce length ${nonceBytes.size} != 32")
                ProtocolHandler.sendError(output, challenge.session_id, "nonce_length_mismatch")
                return
            }

            Log.i(TAG, "Challenge received: session=${challenge.session_id}, nonce=${challenge.nonce.take(16)}…")

            // 2. Biometric prompt (on UI thread)
            val authResult = biometricHandler.awaitAuthentication(
                title = "Unlock ${clientSocket.inetAddress.hostName}",
                subtitle = "Scan fingerprint to unlock your PC",
            )

            if (authResult == null) {
                Log.w(TAG, "Biometric declined by user")
                ProtocolHandler.sendError(output, challenge.session_id, "biometric_declined")
                return
            }

            // 3. Sign the nonce (inside biometric auth context)
            val signature = cryptoManager.sign(data = nonceBytes)
            Log.i(TAG, "Nonce signed: ${signature.size} bytes")

            // 4. Build and send response
            val fingerprint = cryptoManager.getPublicKeyFingerprint() ?: "unknown"
            val response = ResponseMessage(
                session_id = challenge.session_id,
                signature = signature.toHex(),
                public_key_fingerprint = fingerprint,
                device_name = Build.MODEL,
            )

            ProtocolHandler.sendResponse(output, response)
            Log.i(TAG, "Response sent to ${clientSocket.inetAddress}")

        } catch (e: java.net.SocketTimeoutException) {
            Log.e(TAG, "Socket timeout during handshake", e)
        } catch (e: IOException) {
            Log.e(TAG, "I/O error during handshake", e)
        } catch (e: SecurityException) {
            Log.e(TAG, "Security constraint violated", e)
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
            NotificationManager.IMPORTANCE_LOW,  // no sound / heads-up
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
            .setSmallIcon(android.R.drawable.ic_menu_view)  // placeholder
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
    // Status broadcast (to Activity)
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
