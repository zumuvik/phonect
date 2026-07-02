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
import com.phonect.android.logging.LogManager
import com.phonect.android.network.PhonectNetworkService

/**
 * Main (and only) activity of the phonect Android app.
 *
 * Provides:
 * - Service start/stop controls
 * - Status display
 * - Biometric readiness check
 * - Public key management (future: QR-code pairing)
 * - Real-time log display and share
 */
class MainActivity : AppCompatActivity() {

    private lateinit var cryptoManager: CryptoManager
    private lateinit var biometricHandler: BiometricHandler
    private lateinit var statusText: TextView
    private lateinit var fingerprintStatus: TextView
    private lateinit var publicKeyFingerprint: TextView
    private lateinit var logView: TextView
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var shareButton: Button

    private var serviceRunning = false

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val status = intent.getStringExtra(PhonectNetworkService.EXTRA_STATUS) ?: return
            runOnUiThread { updateStatus(status) }
        }
    }

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val line = intent.getStringExtra(LogManager.EXTRA_LOG_LINE) ?: return
            runOnUiThread { appendLog(line) }
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

        // Initialise managers + logger
        LogManager.init(this)
        cryptoManager = CryptoManager(applicationContext)
        biometricHandler = BiometricHandler(this)

        // Bind views
        statusText = findViewById(R.id.status_text)
        fingerprintStatus = findViewById(R.id.fingerprint_status)
        publicKeyFingerprint = findViewById(R.id.public_key_fingerprint)
        logView = findViewById(R.id.log_view)
        startButton = findViewById(R.id.btn_start_service)
        stopButton = findViewById(R.id.btn_stop_service)
        shareButton = findViewById(R.id.btn_share_logs)

        startButton.setOnClickListener { startService() }
        stopButton.setOnClickListener { stopService() }
        shareButton.setOnClickListener { shareLogs() }

        // Register status receiver
        LocalBroadcastManager.getInstance(this)
            .registerReceiver(statusReceiver, IntentFilter(PhonectNetworkService.ACTION_BROADCAST_STATUS))

        // Register log entry receiver
        LocalBroadcastManager.getInstance(this)
            .registerReceiver(logReceiver, IntentFilter(LogManager.ACTION_LOG_ENTRY))

        // Load existing logs
        loadExistingLogs()

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
        LocalBroadcastManager.getInstance(this).unregisterReceiver(logReceiver)
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

    // ------------------------------------------------------------------
    // Log display
    // ------------------------------------------------------------------

    /**
     * Append a single log line to the on-screen log view and auto-scroll.
     */
    private fun appendLog(line: String) {
        logView.append(line + "\n")
        // Auto-scroll to bottom
        val parent = logView.parent as? ScrollView
        parent?.post { parent.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    /**
     * Load the full log file content into the log view on startup.
     */
    private fun loadExistingLogs() {
        val content = LogManager.getLogContent()
        if (content.isNotBlank()) {
            logView.text = content
            // Scroll to bottom
            val parent = logView.parent as? ScrollView
            parent?.post { parent.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    /**
     * Share the log file via Android's share sheet (Intent.ACTION_SEND).
     */
    private fun shareLogs() {
        val intent = LogManager.createShareIntent()
        if (intent != null) {
            startActivity(Intent.createChooser(intent, "Share phonect logs"))
        } else {
            Toast.makeText(this, "LogManager not initialised", Toast.LENGTH_SHORT).show()
        }
    }
}
