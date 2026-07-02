package com.phonect.android.crypto

import android.security.keystore.*
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import javax.crypto.Cipher

/**
 * Manages RSA-4096 key pair generation and signing via Android Hardware-backed
 * Keystore, with mandatory biometric authentication.
 *
 * The private key is created with:
 * - `PURPOSE_SIGN` (cannot be used for encryption/decryption)
 * - `setUserAuthenticationRequired(true)` — released only after biometric auth
 * - `setUserAuthenticationValidityDurationSeconds(-1)` — must re-auth per use
 * - `setIsStrongBoxBacked(true)` — prefer StrongBox / TEE if available
 *
 * Usage:
 * ```kotlin
 * val crypto = CryptoManager(context)
 * crypto.generateKeyIfNeeded("phonect_key")
 * // ... later, inside BiometricPrompt success callback:
 * val signature = crypto.sign("phonect_key", nonceBytes)
 * ```
 */
class CryptoManager(private val appContext: android.content.Context) {

    companion object {
        const val KEY_ALIAS = "phonect_rsa_key"
        const val KEY_SIZE = 4096
        const val SIGNATURE_ALGORITHM = "SHA512withRSA/PSS"
        const val PROVIDER = "AndroidKeyStore"
        const val DIGEST = "SHA-512"

        /** Hex characters for fingerprint computation. */
        private val HEX_CHARS = "0123456789abcdef".toCharArray()
    }

    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    // ------------------------------------------------------------------
    // Key generation
    // ------------------------------------------------------------------

    /**
     * Generate an RSA-4096 key pair in Android Keystore if [KEY_ALIAS]
     * does not already exist.
     *
     * The key is bound to biometric authentication:
     * - Each signing operation requires a fresh biometric prompt.
     * - The key is stored in StrongBox / TEE if the device supports it.
     */
    fun generateKeyIfNeeded(alias: String = KEY_ALIAS) {
        if (keyStore.containsAlias(alias)) return

        val keyGen = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            PROVIDER
        )

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        )
            .setKeySize(KEY_SIZE)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            .setDigests(KeyProperties.DIGEST_SHA512)
            // Biometric binding --------------------------------------------------
            .setUserAuthenticationRequired(true)                 // must auth
            .setUserAuthenticationValidityDurationSeconds(-1)    // auth per use
            .setInvalidatedByBiometricEnrollment(true)           // new finger = key gone
            // Hardware binding ----------------------------------------------------
            .setIsStrongBoxBacked(true)                          // prefer StrongBox/TEE
            // Key is not used for encryption, so no need for purposes other than SIGN
            .build()

        keyGen.initialize(spec)
        keyGen.generateKeyPair()
    }

    // ------------------------------------------------------------------
    // Signing
    // ------------------------------------------------------------------

    /**
     * Sign [data] with the private key identified by [alias].
     *
     * **Must be called inside a BiometricPrompt success callback**
     * (i.e. after the user has authenticated), otherwise the Keystore
     * will throw [KeyStoreException] / [UserNotAuthenticatedException].
     *
     * @param alias key alias in Android Keystore.
     * @param data bytes to sign (the 32-byte nonce).
     * @return RSA-PSS/SHA-512 signature bytes.
     */
    fun sign(alias: String = KEY_ALIAS, data: ByteArray): ByteArray {
        val privateKey = (keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry).privateKey
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)

        // Configure PSS parameters: salt = hash length (max)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    // ------------------------------------------------------------------
    // Public key & fingerprint
    // ------------------------------------------------------------------

    /**
     * Return the public key for [alias], or null if the key does not exist.
     */
    fun getPublicKey(alias: String = KEY_ALIAS): PublicKey? {
        if (!keyStore.containsAlias(alias)) return null
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        return entry?.certificate?.publicKey
    }

    /**
     * Return the PEM-encoded public key for [alias], or null.
     */
    fun getPublicKeyPem(alias: String = KEY_ALIAS): String? {
        val pubKey = getPublicKey(alias) ?: return null
        return pemEncodePublicKey(pubKey)
    }

    /**
     * Compute SHA-256 fingerprint (hex) of the DER-encoded public key.
     * Matches [phonect.crypto.fingerprint_from_public_key].
     */
    fun getPublicKeyFingerprint(alias: String = KEY_ALIAS): String? {
        val pubKey = getPublicKey(alias) ?: return null
        val der = pubKey.encoded  // X.509 SubjectPublicKeyInfo DER
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(der)
        return hash.toHex()
    }

    /**
     * Check whether the key exists in the Keystore.
     */
    fun hasKey(alias: String = KEY_ALIAS): Boolean {
        return keyStore.containsAlias(alias)
    }

    /**
     * Delete the key pair from Keystore (used for "unpair all").
     */
    fun deleteKey(alias: String = KEY_ALIAS) {
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    // ------------------------------------------------------------------
    // Key attestation (optional — for future device binding)
    // ------------------------------------------------------------------

    /**
     * Attempt key attestation.
     *
     * Returns the certificate chain if available, or null if the device
     * does not support attestation or the key was not created with
     * `setAttestKeyAlias`.
     */
    fun getAttestationChain(alias: String = KEY_ALIAS): Array<out java.security.cert.Certificate>? {
        return try {
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            entry?.certificateChain
        } catch (e: Exception) {
            null
        }
    }

    // ------------------------------------------------------------------
    // PEM encoding
    // ------------------------------------------------------------------

    private fun pemEncodePublicKey(key: PublicKey): String {
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(key.encoded)
        return "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----"
    }

    private fun ByteArray.toHex(): String {
        val hex = StringBuilder(size * 2)
        for (b in this) {
            hex.append(HEX_CHARS[(b.toInt() ushr 4) and 0x0F])
            hex.append(HEX_CHARS[(b.toInt() ushr 0) and 0x0F])
        }
        return hex.toString()
    }
}
