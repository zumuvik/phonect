package com.phonect.android.logging

import android.content.Context
import android.content.Intent
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import java.io.File
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Singleton logger that writes timestamped logs to a file and broadcasts
 * new entries for real-time UI display.
 *
 * Format:  [YYYY-MM-DD HH:mm:ss] [LEVEL] [TAG] Message
 *
 * File:  `{filesDir}/phonect_logs.txt`  — rotated (truncated) at 1 MB.
 * Broadcast:  [ACTION_LOG_ENTRY] with [EXTRA_LOG_LINE] on every write.
 *
 * Also delegates to `android.util.Log` for logcat visibility during
 * development and crash reporting.
 */
object LogManager {

    private const val MAX_LOG_SIZE = 1_000_000L   // 1 MB
    private const val LOG_FILE_NAME = "phonect_logs.txt"
    private const val DATE_FORMAT = "yyyy-MM-dd HH:mm:ss"

    const val ACTION_LOG_ENTRY = "com.phonect.android.LOG_ENTRY"
    const val EXTRA_LOG_LINE = "log_line"

    private var appContext: Context? = null
    private var logFile: File? = null
    private var initialized = false
    private val lock = ReentrantLock()
    private val dateFormat = SimpleDateFormat(DATE_FORMAT, Locale.US)

    /**
     * Initialise the logger.  Safe to call multiple times — subsequent calls
     * are no-ops.
     *
     * Should be called early from [PhonectNetworkService.onCreate] and/or
     * [MainActivity.onCreate].
     */
    fun init(context: Context) {
        if (initialized) return
        appContext = context.applicationContext
        logFile = File(context.filesDir, LOG_FILE_NAME)
        rotateIfNeeded()
        initialized = true
    }

    // ── Public logging API ───────────────────────────────────────────────

    fun d(tag: String, message: String) = log(android.util.Log.DEBUG, "DEBUG", tag, message)
    fun i(tag: String, message: String) = log(android.util.Log.INFO, "INFO", tag, message)
    fun w(tag: String, message: String) = log(android.util.Log.WARN, "WARN", tag, message)

    fun e(tag: String, message: String, throwable: Throwable? = null) {
        val full = if (throwable != null) "$message: ${throwable.message}" else message
        log(android.util.Log.ERROR, "ERROR", tag, full)
        // Also log the full stack trace to logcat
        if (throwable != null) {
            android.util.Log.e(tag, message, throwable)
        }
    }

    // ── Internal ─────────────────────────────────────────────────────────

    private fun log(logcatLevel: Int, level: String, tag: String, message: String) {
        val timestamp = dateFormat.format(Date())
        val line = "[$timestamp] [$level] [$tag] $message"

        // Also write to logcat (helpful for adb logcat)
        android.util.Log.println(logcatLevel, tag, message)

        lock.withLock {
            writeToFile(line)
            rotateIfNeeded()
        }

        broadcast(line)
    }

    private fun writeToFile(line: String) {
        val file = logFile ?: return
        try {
            file.appendText(line + "\n")
        } catch (e: Exception) {
            android.util.Log.e("LogManager", "Failed to write log entry", e)
        }
    }

    /**
     * Truncate the log file if it exceeds [MAX_LOG_SIZE].
     */
    private fun rotateIfNeeded() {
        val file = logFile ?: return
        try {
            if (file.exists() && file.length() > MAX_LOG_SIZE) {
                file.writeText("")
            }
        } catch (e: Exception) {
            android.util.Log.e("LogManager", "Failed to rotate log", e)
        }
    }

    /**
     * Broadcast a new log line to the UI via [LocalBroadcastManager].
     */
    private fun broadcast(line: String) {
        val ctx = appContext ?: return
        val intent = Intent(ACTION_LOG_ENTRY).apply {
            putExtra(EXTRA_LOG_LINE, line)
        }
        LocalBroadcastManager.getInstance(ctx).sendBroadcast(intent)
    }

    // ── File access ─────────────────────────────────────────────────────

    /**
     * Return the full current log as a single string.
     */
    fun getLogContent(): String {
        return lock.withLock {
            try {
                logFile?.readText() ?: ""
            } catch (e: Exception) {
                "Error reading logs: ${e.message}"
            }
        }
    }

    /**
     * Clear all log entries: truncate the file on disk.
     */
    fun clearLogs() {
        lock.withLock {
            try {
                logFile?.writeText("")
            } catch (e: Exception) {
                android.util.Log.e("LogManager", "Failed to clear logs", e)
            }
        }
    }
}
