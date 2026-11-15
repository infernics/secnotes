package infernics.notes

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Independent encrypted file area. The passphrase is never persisted: only a random
 * PBKDF2 salt and an AES-GCM encrypted verifier are stored. The derived key exists only
 * in the current unlocked session and is intentionally not registered with biometrics.
 */
object HiddenVault {
    // Neutral private names avoid advertising the existence of a separate area in app storage.
    const val DIRECTORY_NAME = ".media_cache"
    const val METADATA_FILE_NAME = ".media_index"
    private const val METADATA_NAME = METADATA_FILE_NAME
    private const val METADATA_MAGIC = 0x534E4856 // SNHV
    private const val SALT_LENGTH = 16
    private val VERIFIER = "SecNote.HiddenVault.Verifier.v1".toByteArray(Charsets.US_ASCII)

    private fun metadataFile(context: Context) = File(context.filesDir, METADATA_NAME)
    private fun hiddenDirectory(context: Context) = File(context.filesDir, DIRECTORY_NAME)

    fun isConfigured(context: Context): Boolean = metadataFile(context).isFile

    /** One-time setup. There is deliberately no stored password or biometric wrapper. */
    @Synchronized
    fun configure(context: Context, passphrase: String) {
        val generation = StorageGate.currentGeneration()
        StorageGate.withAccess(generation) { configureInSession(context, passphrase) }
    }

    private fun configureInSession(context: Context, passphrase: String) {
        require(passphrase.length >= 12) { "Пароль должен содержать не менее 12 символов." }
        val destination = metadataFile(context)
        val parent = destination.parentFile
        check(parent != null && (parent.isDirectory || parent.mkdirs())) {
            "Не удалось подготовить защищённое хранилище приложения."
        }
        check(!destination.exists()) { "Отдельный пароль уже настроен." }
        check(!hiddenDirectory(context).exists()) { "Файловое пространство уже существует; повторная инициализация запрещена." }

        val salt = Crypto.newSalt()
        var record: ByteArray? = null
        try {
            val createdRecord = createRecord(passphrase, salt)
            record = createdRecord
            val temp = File(destination.parentFile, "$METADATA_NAME.tmp")
            FileOutputStream(temp, false).use { stream ->
                stream.write(createdRecord)
                stream.fd.sync()
            }
            if (!temp.renameTo(destination)) {
                temp.delete()
                error("Не удалось атомарно сохранить ключевой материал.")
            }
            check(hiddenDirectory(context).exists() || hiddenDirectory(context).mkdirs()) {
                "Не удалось создать защищённое файловое пространство."
            }
        } catch (error: Exception) {
            // Do not leave a half-configured store if setup did not commit completely.
            overwriteAndDelete(destination)
            overwriteAndDelete(File(destination.parentFile, "$METADATA_NAME.tmp"))
            overwriteAndDelete(hiddenDirectory(context))
            throw error
        } finally {
            salt.fill(0)
            record?.fill(0)
        }
    }

    /** Returns a session-only key on success; incorrect passwords produce no key. */
    fun unlock(context: Context, passphrase: String): Crypto? {
        if (passphrase.isEmpty()) return null
        val generation = runCatching { StorageGate.currentGeneration() }.getOrNull() ?: return null
        return runCatching {
            StorageGate.withAccess(generation) { unlockInSession(context, passphrase) }
        }.getOrNull()
    }

    private fun unlockInSession(context: Context, passphrase: String): Crypto? {
        val file = metadataFile(context)
        if (!file.isFile) return null
        val record = runCatching { file.readBytes() }.getOrNull() ?: return null
        val unlocked = try {
            unlockFromRecord(passphrase, record)
        } finally {
            record.fill(0)
        } ?: return null

        // Recover only an empty/missing directory after the password has authenticated.
        // Never recreate metadata or replace the key if encrypted payloads are orphaned.
        val directory = hiddenDirectory(context)
        if ((!directory.exists() && !directory.mkdirs()) || !directory.isDirectory) {
            unlocked.destroy()
            return null
        }
        return unlocked
    }

    fun matchesPassphrase(context: Context, passphrase: String): Boolean {
        val key = unlock(context, passphrase) ?: return false
        key.destroy()
        return true
    }

    /** Pure helpers permit JVM tests of the verifier without an Android Context. */
    internal fun createRecord(passphrase: String, salt: ByteArray): ByteArray {
        require(passphrase.length >= 12)
        require(salt.size == SALT_LENGTH)
        val crypto = Crypto.fromPassphrase(passphrase, salt)
        return try {
            val encryptedVerifier = crypto.encrypt(VERIFIER)
            try {
                ByteBuffer.allocate(4 + SALT_LENGTH + encryptedVerifier.size)
                    .putInt(METADATA_MAGIC)
                    .put(salt)
                    .put(encryptedVerifier)
                    .array()
            } finally {
                encryptedVerifier.fill(0)
            }
        } finally {
            crypto.destroy()
        }
    }

    internal fun unlockFromRecord(passphrase: String, record: ByteArray): Crypto? {
        if (passphrase.isEmpty()) return null
        var salt: ByteArray? = null
        var encryptedVerifier: ByteArray? = null
        var plaintextVerifier: ByteArray? = null
        var candidate: Crypto? = null
        return try {
            require(record.size >= 4 + SALT_LENGTH + 12 + VERIFIER.size + 16)
            val buffer = ByteBuffer.wrap(record)
            require(buffer.int == METADATA_MAGIC)
            val saltBytes = ByteArray(SALT_LENGTH).also(buffer::get)
            salt = saltBytes
            val encryptedBytes = ByteArray(buffer.remaining()).also(buffer::get)
            encryptedVerifier = encryptedBytes
            val derivedCrypto = Crypto.fromPassphrase(passphrase, saltBytes)
            candidate = derivedCrypto
            val verifierBytes = derivedCrypto.decrypt(encryptedBytes)
            plaintextVerifier = verifierBytes
            if (MessageDigest.isEqual(verifierBytes, VERIFIER)) {
                candidate = null
                derivedCrypto
            } else {
                null
            }
        } catch (_: Exception) {
            null
        } finally {
            salt?.fill(0)
            encryptedVerifier?.fill(0)
            plaintextVerifier?.fill(0)
            candidate?.destroy()
        }
    }

    private fun overwriteAndDelete(entry: File) {
        if (!entry.exists()) return
        if (entry.isDirectory) {
            entry.listFiles()?.forEach(::overwriteAndDelete)
            entry.delete()
            return
        }
        runCatching {
            val length = entry.length()
            FileOutputStream(entry, false).use { stream ->
                val zeros = ByteArray(4096)
                var remaining = length
                while (remaining > 0) {
                    val count = minOf(zeros.size.toLong(), remaining).toInt()
                    stream.write(zeros, 0, count)
                    remaining -= count
                }
                stream.fd.sync()
            }
        }
        entry.delete()
    }
}
