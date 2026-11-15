package infernics.notes

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Stores a salted PBKDF2 verifier for the emergency-destruction password.
 * The password itself is never persisted. Verification is performed before the normal
 * vault-password check on the lock screen, so the same input field supports both passwords.
 */
object PanicCredential {
    private const val FILE_NAME = "panic.credential"
    private const val MAGIC = 0x53435031 // SCP1
    private const val ITERATIONS = 350_000
    private const val SALT_LENGTH = 16
    private const val VERIFIER_LENGTH = 32
    private const val RECORD_LENGTH = 4 + SALT_LENGTH + VERIFIER_LENGTH
    private const val KEY_BITS = VERIFIER_LENGTH * 8

    fun isConfigured(context: Context): Boolean = credentialFile(context).isFile

    @Synchronized
    fun set(context: Context, password: String) {
        require(password.length >= 8) {
            "Секретный пароль должен содержать не менее 8 символов."
        }
        val salt = ByteArray(SALT_LENGTH).also { SecureRandom().nextBytes(it) }
        val record = try {
            createRecord(password, salt)
        } finally {
            salt.fill(0)
        }
        try {
            writeAtomically(credentialFile(context), record)
        } finally {
            record.fill(0)
        }
    }

    fun verify(context: Context, password: String): Boolean {
        if (password.isEmpty()) return false
        val file = credentialFile(context)
        if (!file.isFile) return false
        val record = runCatching { file.readBytes() }.getOrNull() ?: return false
        return try {
            verifyRecord(password, record)
        } finally {
            record.fill(0)
        }
    }

    /** Returns true only when the verifier and its temporary file are no longer present. */
    @Synchronized
    fun remove(context: Context): Boolean {
        val file = credentialFile(context)
        val temporary = File(file.parentFile, "$FILE_NAME.tmp")
        bestEffortOverwrite(file)
        bestEffortOverwrite(temporary)
        val fileDeleted = !file.exists() || file.delete()
        val tempDeleted = !temporary.exists() || temporary.delete()
        return fileDeleted && tempDeleted && !file.exists() && !temporary.exists()
    }

    /** Pure helpers are internal so the verifier format can be unit-tested on the JVM. */
    internal fun createRecord(password: String, salt: ByteArray): ByteArray {
        require(password.length >= 8)
        require(salt.size == SALT_LENGTH)
        val verifier = derive(password, salt)
        return try {
            ByteBuffer.allocate(RECORD_LENGTH)
                .putInt(MAGIC)
                .put(salt)
                .put(verifier)
                .array()
        } finally {
            verifier.fill(0)
        }
    }

    internal fun verifyRecord(password: String, record: ByteArray): Boolean {
        if (password.isEmpty() || record.size != RECORD_LENGTH) return false
        var salt: ByteArray? = null
        var expected: ByteArray? = null
        var actual: ByteArray? = null
        return try {
            val buffer = ByteBuffer.wrap(record)
            if (buffer.int != MAGIC) return false
            salt = ByteArray(SALT_LENGTH).also(buffer::get)
            expected = ByteArray(VERIFIER_LENGTH).also(buffer::get)
            actual = derive(password, salt)
            MessageDigest.isEqual(expected, actual)
        } catch (_: Exception) {
            false
        } finally {
            salt?.fill(0)
            expected?.fill(0)
            actual?.fill(0)
        }
    }

    private fun derive(password: String, salt: ByteArray): ByteArray {
        val chars = password.toCharArray()
        val spec = PBEKeySpec(chars, salt, ITERATIONS, KEY_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            chars.fill('\u0000')
        }
    }

    private fun credentialFile(context: Context) = File(context.filesDir, FILE_NAME)

    private fun writeAtomically(destination: File, bytes: ByteArray) {
        check(destination.parentFile?.let { it.exists() || it.mkdirs() } == true) {
            "Не удалось подготовить приватное хранилище."
        }
        val temporary = File(destination.parentFile, "$FILE_NAME.tmp")
        try {
            FileOutputStream(temporary, false).use { stream ->
                stream.write(bytes)
                stream.flush()
                stream.fd.sync()
            }
            if (!temporary.renameTo(destination)) {
                FileOutputStream(destination, false).use { stream ->
                    stream.write(bytes)
                    stream.flush()
                    stream.fd.sync()
                }
                check(temporary.delete() || !temporary.exists()) {
                    "Не удалось удалить временный файл секрета."
                }
            }
            check(destination.isFile && destination.length() == RECORD_LENGTH.toLong()) {
                "Не удалось проверить сохранение секретного пароля."
            }
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun bestEffortOverwrite(file: File) {
        if (!file.isFile) return
        runCatching {
            val length = file.length()
            java.io.RandomAccessFile(file, "rw").use { random ->
                random.seek(0L)
                val zeros = ByteArray(4096)
                var remaining = length
                while (remaining > 0L) {
                    val count = minOf(zeros.size.toLong(), remaining).toInt()
                    random.write(zeros, 0, count)
                    remaining -= count.toLong()
                }
                random.fd.sync()
            }
        }
    }
}
