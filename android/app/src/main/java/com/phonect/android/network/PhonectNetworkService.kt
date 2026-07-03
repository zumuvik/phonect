package com.phonect.android.network

import android.app.*
import android.bluetooth.*
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
import java.util.UUID

/**
 * Foreground Service that listens for Bluetooth RFCOMM connections from the PC.
 *
 * - Advertises a Bluetooth server socket with a fixed UUID.
 * - When the PC connects (after waking from sleep), performs TOFU
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

        /** Unique UUID for phonect Bluetooth RFCOMM service. */
        private val SERVICE_UUID: UUID =
            UUID.fromString("fa87c0d0-afac-11de-8a39-0800200c9a66")

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
    private var bluetoothServerSocket: BluetoothServerSocket? = null
    private var bluetoothAdapter: BluetoothAdapter? = null

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

        bluetoothAdapter = BluetoothAdapter.getDefaultAdapter()
        if (bluetoothAdapter == null) {
            LogManager.w(TAG, "Device does not support Bluetooth")
        }

        serviceScope.launch {
            cryptoManager.generateKeyIfNeeded()
            LogManager.i(TAG, "Key generation completed")
        }

        LogManager.i(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val notification = buildNotification("Listening for PC via Bluetooth…", false)
                startForeground(NOTIFICATION_ID, notification)
                startBluetoothListener()
            }
            ACTION_STOP -> stopBluetoothListener()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopBluetoothListener()
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
    // Bluetooth server listener
    // ------------------------------------------------------------------

    private fun startBluetoothListener() {
        if (listenJob?.isActive == true) return
        val adapter = bluetoothAdapter ?: return

        listenJob = serviceScope.launch {
            try {
                // Use listenUsingRfcommWithServiceRecord for SDP registration
                bluetoothServerSocket = adapter.listenUsingRfcommWithServiceRecord(
                    "phonect",
                    SERVICE_UUID,
                )
                LogManager.i(TAG, "Bluetooth RFCOMM listening on $SERVICE_UUID")
                updateNotification("Listening for PC via Bluetooth")
                broadcastStatus("listening:bt")

                while (isActive) {
                    try {
                        val socket = bluetoothServerSocket?.accept() ?: break
                        val remoteDevice = socket.remoteDevice
                        LogManager.i(
                            TAG,
                            "Bluetooth connection from ${remoteDevice.name} (${remoteDevice.address})",
                        )

                        // Handle connection in a new coroutine
                        launch {
                            handleBtConnection(socket)
                        }
                    } catch (e: IOException) {
                        if (isActive) {
                            LogManager.e(TAG, "Bluetooth accept error", e)
                        }
                    }
                }
            } catch (e: SecurityException) {
                LogManager.e(TAG, "Bluetooth permission denied", e)
                updateNotification("BT permission denied")
                broadcastStatus("error:bt_permission")
            } catch (e: IOException) {
                LogManager.e(TAG, "Bluetooth server error", e)
                updateNotification("Error: ${e.message ?: "unknown"}")
                broadcastStatus("error")
            } finally {
                try { bluetoothServerSocket?.close() } catch (_: Exception) {}
                LogManager.i(TAG, "Bluetooth listener stopped")
                updateNotification("Service stopped")
                broadcastStatus("stopped")
            }
        }
    }

    private fun stopBluetoothListener() {
        listenJob?.cancel()
        try { bluetoothServerSocket?.close() } catch (_: Exception) {}
        bluetoothServerSocket = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ------------------------------------------------------------------
    // Bluetooth connection handler
    // ------------------------------------------------------------------

    private suspend fun handleBtConnection(socket: BluetoothSocket) {
        var input: InputStream? = null
        var output: OutputStream? = null
        try {
            input = socket.inputStream
            output = socket.outputStream

            // ── Step 1: Read pair_hello (PC sends first) ─────────────
            val hello = ProtocolHandler.readPairHello(input)
            if (hello == null) {
                LogManager.w(TAG, "No PairHello from PC — aborting")
                return
            }
            LogManager.i(TAG, "PairHello received from PC")

            val pcPem = hello.public_key_pem
            val pcFp = hello.public_key_fingerprint
            val pcName = hello.device_name

            // ── Step 2: Send pair_accept with phone's public key ──
            val pubKeyPem = cryptoManager.getPublicKeyPem()
            val pubKeyFp = cryptoManager.getPublicKeyFingerprint()
            if (pubKeyPem == null || pubKeyFp == null) {
                LogManager.e(TAG, "Phone key not ready — skipping handshake")
                return
            }

            val accept = PairAcceptMessage(
                session_id = hello.session_id,
                public_key_pem = pubKeyPem,
                public_key_fingerprint = pubKeyFp,
            )
            ProtocolHandler.sendPairAccept(output, accept)
            LogManager.i(TAG, "PairAccept sent to PC")

            // ── Step 3: TOFU — save PC key if new ─────────────────
            val trustedPc = findTrustedPeerByFingerprint(pcFp)
            if (trustedPc == null) {
                saveTrustedPc(
                    name = pcName,
                    publicKeyPem = pcPem,
                    publicKeyFingerprint = pcFp,
                )
                LogManager.i(TAG, "TOFU: paired with PC $pcName (${pcFp.take(16)}…)")
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
            val savedPc = findTrustedPeerByFingerprint(pcFp)
            if (savedPc != null &&
                challenge.pc_signature != null &&
                challenge.pc_key_fingerprint != null
            ) {
                val pcValid = cryptoManager.verifyPcSignature(
                    nonce = nonceBytes,
                    signature = challenge.pc_signature!!,
                    pcPublicKeyPem = savedPc.publicKeyPem,
                )
                if (!pcValid) {
                    LogManager.w(TAG, "Mutual auth FAILED — PC signature invalid for ${savedPc.name}")
                    return
                }
                LogManager.i(TAG, "Mutual auth OK — PC verified")
            } else if (getTrustedPcs().isNotEmpty() && savedPc == null) {
                LogManager.w(TAG, "Untrusted PC $pcFp — no matching trusted record")
                return
            }

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
                title = "Unlock ${savedPc?.name ?: pcName}",
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
            LogManager.e(TAG, "I/O error during BT handshake", e)
        } catch (e: SecurityException) {
            LogManager.e(TAG, "Security constraint: ${e.message}")
        } catch (e: Exception) {
            LogManager.e(TAG, "Unexpected error during BT handshake", e)
        } finally {
            try {
                input?.close()
                output?.close()
                socket.close()
            } catch (_: Exception) {}
            LogManager.i(TAG, "Bluetooth connection closed")
        }
    }

    // ------------------------------------------------------------------
    // Trusted PC persistence (keyed by fingerprint, no IP address)
    // ------------------------------------------------------------------

    private fun saveTrustedPc(
        name: String,
        publicKeyPem: String,
        publicKeyFingerprint: String,
    ) {
        val current = getTrustedPcs().toMutableList()

        val idx = current.indexOfFirst { it.publicKeyFingerprint == publicKeyFingerprint }
        val pc = PairedPc(
            name = name,
            hostname = name,
            ipAddress = "",          // Not used — BT MAC replaces IP
            port = 0,               // Not used
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
