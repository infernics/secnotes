package infernics.notes

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Password verifier and salt storage.
 *
 * The content key is still derived from the user's main password with PBKDF2-HMAC-SHA256.
 * The random PBKDF2 salt is wrapped by an app-owned Android Keystore AES-GCM key. This
 * preserves the existing content-key format while adding a non-exportable device-bound
 * key that can be deleted during emergency cryptographic erasure.
 *
 * Compatibility: versions 1.3.2 and 1.3.3 stored a raw 16-byte salt. On the first successful unlock
 * after updating, that legacy salt is transparently wrapped in Android Keystore without
 * re-encrypting any notes or vault files.
 */
object Vault {
    private const val SALT_KEY_ALIAS = "SecNoteVaultSaltKey"
    private const val SALT_MAGIC = 0x53434B31 // SCK1
    private const val SALT_LENGTH = 16
    private const val GCM_IV_LENGTH = 12
    private const val TAG_BITS = 128

    private fun saltFile(context: Context) = File(context.filesDir, "key.salt")
    private fun checkFile(context: Context) = File(context.filesDir, "key.check")

    fun isSetup(context: Context): Boolean = saltFile(context).exists() && checkFile(context).exists()

    @Synchronized
    fun create(context: Context, passphrase: String): Crypto {
        require(passphrase.length >= 8) { "Пароль должен содержать не менее 8 символов" }
        deleteSaltWrappingKey()
        val salt = Crypto.newSalt()
        val crypto = try {
            Crypto.fromPassphrase(passphrase, salt)
        } catch (error: Exception) {
            salt.fill(0)
            throw error
        }
        var created = false
        try {
            val wrappedSalt = wrapSalt(salt)
            try {
                writeAtomically(saltFile(context), wrappedSalt)
            } finally {
                wrappedSalt.fill(0)
            }
            val verificationBlob = crypto.encrypt("verify")
            try {
                writeAtomically(checkFile(context), verificationBlob)
            } finally {
                verificationBlob.fill(0)
            }
            created = true
            return crypto
        } finally {
            salt.fill(0)
            if (!created) crypto.destroy()
        }
    }

    @Synchronized
    fun unlock(context: Context, passphrase: String): Crypto? {
        if (!isSetup(context)) return null
        var storedSalt: ByteArray? = null
        var salt: ByteArray? = null
        return try {
            val storedBytes = saltFile(context).readBytes()
            storedSalt = storedBytes
            val recoveredSalt = if (storedBytes.size == SALT_LENGTH) {
                storedBytes.copyOf() // 1.3.2/1.3.3 legacy raw PBKDF2 salt
            } else {
                unwrapSalt(storedBytes)
            }
            salt = recoveredSalt
            if (recoveredSalt.size != SALT_LENGTH) return null

            val crypto = Crypto.fromPassphrase(passphrase, recoveredSalt)
            if (!ensureSaltWrapped(context, crypto)) {
                crypto.destroy()
                return null
            }
            crypto
        } catch (_: Exception) {
            null
        } finally {
            storedSalt?.fill(0)
            salt?.fill(0)
        }
    }

    /**
     * Verifies an already-unlocked vault key and makes sure its PBKDF2 salt is protected
     * by Android Keystore. This is also called after biometric unlock: otherwise a user
     * upgrading from 1.3.2/1.3.3 could enable the panic password without migrating the old
     * plaintext salt, weakening cryptographic erasure.
     */
    @Synchronized
    fun ensureSaltWrapped(context: Context, crypto: Crypto): Boolean {
        var storedSalt: ByteArray? = null
        var recoveredSalt: ByteArray? = null
        var checkBlob: ByteArray? = null
        var wrapped: ByteArray? = null
        return try {
            val salt = saltFile(context)
            val check = checkFile(context)
            if (!salt.isFile || !check.isFile) return false

            val storedBytes = salt.readBytes()
            storedSalt = storedBytes
            val isLegacySalt = storedBytes.size == SALT_LENGTH
            val saltBytes = if (isLegacySalt) storedBytes.copyOf() else unwrapSalt(storedBytes)
            recoveredSalt = saltBytes
            if (saltBytes.size != SALT_LENGTH) return false

            val checkBytes = check.readBytes()
            checkBlob = checkBytes
            if (crypto.decryptToText(checkBytes) != "verify") return false

            if (isLegacySalt) {
                val wrappedBytes = wrapSalt(saltBytes)
                wrapped = wrappedBytes
                writeAtomically(salt, wrappedBytes)
            }
            true
        } catch (_: Exception) {
            false
        } finally {
            storedSalt?.fill(0)
            recoveredSalt?.fill(0)
            checkBlob?.fill(0)
            wrapped?.fill(0)
        }
    }

    @Synchronized
    internal fun matchesPassphrase(context: Context, passphrase: String): Boolean {
        var stored: ByteArray? = null
        var salt: ByteArray? = null
        var checkBlob: ByteArray? = null
        var candidate: Crypto? = null
        return try {
            if (!isSetup(context)) return false
            val storedBytes = saltFile(context).readBytes()
            stored = storedBytes
            val rawSalt = if (storedBytes.size == SALT_LENGTH) storedBytes.copyOf() else unwrapSalt(storedBytes)
            salt = rawSalt
            checkBlob = checkFile(context).readBytes()
            val crypto = Crypto.fromPassphrase(passphrase, rawSalt)
            candidate = crypto
            crypto.decryptToText(checkBlob) == "verify"
        } catch (_: Exception) {
            false
        } finally {
            candidate?.destroy()
            stored?.fill(0)
            salt?.fill(0)
            checkBlob?.fill(0)
        }
    }

    /** Export the portable PBKDF2 salt only after the currently unlocked key verifies. */
    @Synchronized
    internal fun exportSaltForBackup(context: Context, crypto: Crypto): ByteArray {
        var stored: ByteArray? = null
        var salt: ByteArray? = null
        var checkBlob: ByteArray? = null
        return try {
            check(File(context.filesDir, "key.check").isFile) { "Основное хранилище не настроено." }
            val storedBytes = saltFile(context).readBytes()
            stored = storedBytes
            val rawSalt = if (storedBytes.size == SALT_LENGTH) storedBytes.copyOf() else unwrapSalt(storedBytes)
            salt = rawSalt
            check(rawSalt.size == SALT_LENGTH) { "Некорректная соль основного хранилища." }
            val checkBytes = checkFile(context).readBytes()
            checkBlob = checkBytes
            require(crypto.decryptToText(checkBytes) == "verify") { "Ключ текущего хранилища не подтверждён." }
            rawSalt.copyOf()
        } finally {
            stored?.fill(0)
            salt?.fill(0)
            checkBlob?.fill(0)
        }
    }

    /** Install a portable salt on this device, re-wrapping it with this device's Keystore. */
    @Synchronized
    internal fun installPortableState(context: Context, salt: ByteArray, crypto: Crypto) {
        require(salt.size == SALT_LENGTH) { "Некорректная соль резервной копии." }
        val wrappedSalt = wrapSalt(salt)
        val checkBlob = crypto.encrypt("verify")
        try {
            writeAtomically(saltFile(context), wrappedSalt)
            writeAtomically(checkFile(context), checkBlob)
        } finally {
            wrappedSalt.fill(0)
            checkBlob.fill(0)
        }
    }

    private fun wrapSalt(salt: ByteArray): ByteArray {
        require(salt.size == SALT_LENGTH)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSaltWrappingKey())
        val encrypted = cipher.doFinal(salt)
        return try {
            ByteBuffer.allocate(4 + GCM_IV_LENGTH + encrypted.size)
                .putInt(SALT_MAGIC)
                .put(cipher.iv)
                .put(encrypted)
                .array()
        } finally {
            encrypted.fill(0)
        }
    }

    private fun unwrapSalt(blob: ByteArray): ByteArray {
        require(blob.size >= 4 + GCM_IV_LENGTH + 16) { "Повреждён ключевой материал" }
        val buffer = ByteBuffer.wrap(blob)
        require(buffer.int == SALT_MAGIC) { "Неизвестный формат ключевого материала" }
        val iv = ByteArray(GCM_IV_LENGTH).also { buffer.get(it) }
        val encrypted = ByteArray(buffer.remaining()).also { buffer.get(it) }
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = keyStore.getKey(SALT_KEY_ALIAS, null) as? SecretKey
                ?: error("Ключ хранилища Android недоступен")
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
                doFinal(encrypted)
            }
        } finally {
            iv.fill(0)
            encrypted.fill(0)
        }
    }

    private fun getOrCreateSaltWrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(SALT_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            SALT_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    private fun deleteSaltWrappingKey() {
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(SALT_KEY_ALIAS)) keyStore.deleteEntry(SALT_KEY_ALIAS)
        }
    }

    private fun writeAtomically(destination: File, bytes: ByteArray) {
        val temp = File(destination.parentFile, destination.name + ".tmp")
        FileOutputStream(temp, false).use { stream ->
            stream.write(bytes)
            stream.fd.sync()
        }
        if (!temp.renameTo(destination)) {
            FileOutputStream(destination, false).use { stream ->
                stream.write(bytes)
                stream.fd.sync()
            }
            temp.delete()
        }
    }
}
