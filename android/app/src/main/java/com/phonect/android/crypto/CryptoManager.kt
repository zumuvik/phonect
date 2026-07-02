package com.phonect.android.crypto

import android.security.keystore.*
import androidx.biometric.BiometricPrompt
import java.security.*
import java.security.spec.PSSParameterSpec

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
 * Usage (biometric-bound signing):
 * ```kotlin
 * val crypto = CryptoManager(context)
 * crypto.generateKeyIfNeeded()
 *
 * // Inside the biometric flow:
 * val signature = crypto.getInitializedSignature()
 * val cryptoObj = BiometricPrompt.CryptoObject(signature)
 * // → pass to BiometricPrompt.authenticate(promptInfo, cryptoObj)
 * // → on success, extract Signature from result.cryptoObject.signature
 * // → signature.update(nonce); val signed = signature.sign()
 * ```
 */
class CryptoManager(private val appContext: android.content.Context) {

    companion object {
        const val KEY_ALIAS = "phonect_rsa_key"
        const val KEY_SIZE = 4096
        const val SIGNATURE_ALGORITHM = "SHA512withRSA/PSS"
        const val PROVIDER = "AndroidKeyStore"

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
            .build()

        keyGen.initialize(spec)
        keyGen.generateKeyPair()
    }

    // ------------------------------------------------------------------
    // Biometric-bound signing (CryptoObject flow)
    // ------------------------------------------------------------------

    /**
     * Create and initialize a [Signature] instance bound to the Keystore
     * private key.
     *
     * The returned [Signature] is already in "sign" mode (``initSign`` called).
     * Wrap it in [BiometricPrompt.CryptoObject] and pass to
     * ``prompt.authenticate(promptInfo, cryptoObject)``.
     *
     * After successful biometric auth, extract the validated Signature
     * from ``result.cryptoObject.signature``, call ``update(nonce)`` and
     * ``sign()`` to produce the final signature.
     *
     * @param alias key alias in Android Keystore.
     * @return initialized [Signature] ready to be wrapped in CryptoObject.
     * @throws KeyStoreException if the key does not exist or is inaccessible.
     * @throws UnrecoverableKeyException if the key cannot be retrieved.
     */
    @Throws(KeyStoreException::class, UnrecoverableKeyException::class, NoSuchAlgorithmException::class)
    fun getInitializedSignature(alias: String = KEY_ALIAS): Signature {
        val privateKey = (keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry).privateKey
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        return signature
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
    // Key attestation (optional)
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

    // ======================================================================
    // Mutual auth: verify PC signature
    // ======================================================================

    /**
     * Verify an RSA-PSS signature over [nonce] that was made by the PC's
     * private key.  The PC's public key is obtained from [pcPublicKeyPem].
     *
     * @param nonce the challenge nonce (raw 32 bytes).
     * @param signature hex-encoded RSA-4096 PSS/SHA-512 signature.
     * @param pcPublicKeyPem PEM-encoded PC public key (X.509 SubjectPublicKeyInfo).
     * @return true if the signature is valid.
     */
    fun verifyPcSignature(
        nonce: ByteArray,
        signature: String,
        pcPublicKeyPem: String,
    ): Boolean {
        return try {
            val sigBytes = hexToByteArray(signature)
            val pubKey = parsePemPublicKey(pcPublicKeyPem)

            val verifier = Signature.getInstance(SIGNATURE_ALGORITHM)
            verifier.initVerify(pubKey)
            verifier.update(nonce)
            verifier.verify(sigBytes)
        } catch (e: Exception) {
            Log.e("CryptoManager", "PC signature verification failed", e)
            false
        }
    }

    /**
     * Parse a PEM-encoded X.509 SubjectPublicKeyInfo into a [PublicKey].
     */
    private fun parsePemPublicKey(pem: String): PublicKey {
        val cleaned = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\\s".toRegex(), "")
        val der = Base64.getDecoder().decode(cleaned)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(X509EncodedKeySpec(der))
    }

    /** Convert hex string to ByteArray. */
    private fun hexToByteArray(hex: String): ByteArray {
        val cleaned = hex.replace(" ", "").lowercase()
        return ByteArray(cleaned.length / 2) {
            ((cleaned[it * 2].digitToInt(16) shl 4) + cleaned[it * 2 + 1].digitToInt(16)).toByte()
        }
    }
}
