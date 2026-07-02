package com.phonect.android.biometric

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors

/**
 * Wraps AndroidX [BiometricPrompt] and exposes a suspend function
 * that returns the crypto object when the user authenticates.
 *
 * The [CryptoManager.sign] call happens **inside** the BiometricPrompt
 * success callback, so the Keystore key is unlocked.
 */

class BiometricHandler(private val activity: FragmentActivity) {

    /**
     * Check if biometric authentication is available on this device.
     *
     * @return [BiometricResult] indicating availability or error.
     */
    fun canAuthenticate(): BiometricResult {
        val manager = BiometricManager.from(activity)
        return when (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricResult.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricResult.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricResult.HW_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricResult.NOT_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricResult.SECURITY_UPDATE
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> BiometricResult.UNSUPPORTED
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> BiometricResult.UNKNOWN
            else -> BiometricResult.UNKNOWN
        }
    }

    /**
     * Show the system BiometricPrompt and wait for the user to authenticate.
     *
     * On success, [onSuccess] is called **inside** the auth context,
     * so the Keystore key is available for signing.
     *
     * @param title Prompt title.
     * @param subtitle Prompt subtitle.
     * @param negativeButtonText "Cancel" text.
     * @param onSuccess Called with the [BiometricPrompt.AuthenticationResult] after auth.
     * @param onError Called with error code + message on failure.
     */
    fun promptAuthentication(
        title: String = "Unlock laptop",
        subtitle: String = "Scan fingerprint to unlock your PC",
        negativeButtonText: String = "Cancel",
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onError: (errorCode: Int, errString: String) -> Unit = { _, _ -> },
    ) {
        if (activity.isFinishing) return

        val executor = Executors.newSingleThreadExecutor()

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onSuccess(result)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                onError(errorCode, errString.toString())
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // Fingerprint not recognised — prompt stays open, do nothing.
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeButtonText)
            .setConfirmationRequired(false)   // immediate match, no extra tap
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        prompt.authenticate(promptInfo)
    }

    /**
     * Show biometric prompt and return a [CompletableDeferred] that resolves
     * when the user authenticates or cancels.
     *
     * Returns the [BiometricPrompt.AuthenticationResult] on success, null on cancel/error.
     */
    suspend fun awaitAuthentication(
        title: String = "Unlock laptop",
        subtitle: String = "Scan fingerprint to unlock your PC",
    ): BiometricPrompt.AuthenticationResult? {
        val deferred = CompletableDeferred<BiometricPrompt.AuthenticationResult?>()

        withContext(Dispatchers.Main) {
            promptAuthentication(
                title = title,
                subtitle = subtitle,
                onSuccess = { result -> deferred.complete(result) },
                onError = { _, _ -> deferred.complete(null) },
            )
        }

        return deferred.await()
    }
}

// ---------------------------------------------------------------------------
// Result enum
// ---------------------------------------------------------------------------

enum class BiometricResult {
    AVAILABLE,
    NO_HARDWARE,
    HW_UNAVAILABLE,
    NOT_ENROLLED,
    SECURITY_UPDATE,
    UNSUPPORTED,
    UNKNOWN,
}
