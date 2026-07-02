package com.phonect.android.ui

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.phonect.android.R
import com.phonect.android.biometric.BiometricHandler
import com.phonect.android.biometric.BiometricResult
import com.phonect.android.crypto.CryptoManager
import com.phonect.android.network.PhonectNetworkService

/**
 * Main (and only) activity of the phonect Android app.
 *
 * Provides:
 * - Service start/stop controls
 * - Status display
 * - Biometric readiness check
 * - Public key management (future: QR-code pairing)
 */
class MainActivity : AppCompatActivity() {

    private lateinit var cryptoManager: CryptoManager
    private lateinit var biometricHandler: BiometricHandler
    private lateinit var statusText: TextView
    private lateinit var fingerprintStatus: TextView
    private lateinit var publicKeyFingerprint: TextView
    private lateinit var startButton: Button
    private lateinit var stopButton: Button

    private var serviceRunning = false

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val status = intent.getStringExtra(PhonectNetworkService.EXTRA_STATUS) ?: return
            runOnUiThread { updateStatus(status) }
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // ── Critical: register this Activity for BiometricPrompt ─────────
        // Without this, PhonectNetworkService.handleConnection will not find
        // a FragmentActivity to show BiometricPrompt on, and will abort the
        // handshake with "no_ui_context".
        PhonectNetworkService.setCurrentActivity(this)

        // Initialise managers
        cryptoManager = CryptoManager(applicationContext)
        biometricHandler = BiometricHandler(this)

        // Bind views
        statusText = findViewById(R.id.status_text)
        fingerprintStatus = findViewById(R.id.fingerprint_status)
        publicKeyFingerprint = findViewById(R.id.public_key_fingerprint)
        startButton = findViewById(R.id.btn_start_service)
        stopButton = findViewById(R.id.btn_stop_service)

        startButton.setOnClickListener { startService() }
        stopButton.setOnClickListener { stopService() }

        // Register status receiver
        LocalBroadcastManager.getInstance(this)
            .registerReceiver(statusReceiver, IntentFilter(PhonectNetworkService.ACTION_BROADCAST_STATUS))

        // Initial UI state
        updateBiometricStatus()
        updateKeyInfo()
    }

    override fun onResume() {
        super.onResume()
        // Re-register activity reference in case it was cleared
        PhonectNetworkService.setCurrentActivity(this)
    }

    override fun onDestroy() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(statusReceiver)
        super.onDestroy()
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    private fun startService() {
        val intent = Intent(this, PhonectNetworkService::class.java).apply {
            action = PhonectNetworkService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        serviceRunning = true
        updateStatus("starting")
        startButton.isEnabled = false
        stopButton.isEnabled = true
    }

    private fun stopService() {
        val intent = Intent(this, PhonectNetworkService::class.java).apply {
            action = PhonectNetworkService.ACTION_STOP
        }
        startService(intent)
        serviceRunning = false
        startButton.isEnabled = true
        stopButton.isEnabled = false
        updateStatus("stopped")
    }

    // ------------------------------------------------------------------
    // UI updates
    // ------------------------------------------------------------------

    private fun updateStatus(status: String) {
        statusText.text = when {
            status.startsWith("listening:") -> {
                val port = status.substringAfter(":")
                getString(R.string.status_listening, port.toIntOrNull() ?: 9876)
            }
            status == "stopped" -> getString(R.string.status_stopped)
            status == "starting" -> "Starting…"
            status == "error" -> "Error — check logs"
            status == "wifi_connected" -> "Wi-Fi connected"
            status == "wifi_disconnected" -> "Wi-Fi disconnected"
            else -> status
        }
    }

    private fun updateBiometricStatus() {
        val result = biometricHandler.canAuthenticate()
        fingerprintStatus.text = when (result) {
            BiometricResult.AVAILABLE -> "✓ Biometric ready"
            BiometricResult.NO_HARDWARE -> "✗ No biometric hardware"
            BiometricResult.HW_UNAVAILABLE -> "✗ Hardware unavailable"
            BiometricResult.NOT_ENROLLED -> "⚠ No fingerprints enrolled"
            BiometricResult.SECURITY_UPDATE -> "⚠ Security update required"
            BiometricResult.UNSUPPORTED -> "✗ Biometric not supported"
            BiometricResult.UNKNOWN -> "? Unknown biometric status"
        }
    }

    private fun updateKeyInfo() {
        val fp = cryptoManager.getPublicKeyFingerprint()
        publicKeyFingerprint.text = if (fp != null) {
            "Public key: ${fp.take(16)}…"
        } else {
            "No key generated yet"
        }
    }
}
