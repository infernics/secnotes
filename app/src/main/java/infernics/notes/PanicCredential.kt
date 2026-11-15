package infernics.notes

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Stores only a salted PBKDF2 verifier for the emergency-destruction password.
 * The secret itself is never persisted. The verifier is intentionally checked before
 * the ordinary password verifier on the lock screen.
 */
object PanicCredential {
    private const val FILE_NAME = "panic.credential"
    private const val MAGIC = 0x53435031 // SCP1
    private const val ITERATIONS = 350_000
    private const val SALT_LENGTH = 16
    private const val VERIFIER_LENGTH = 32
    private const val KEY_BITS = VERIFIER_LENGTH * 8

    fun isConfigured(context: Context): Boolean = credentialFile(context).isFile

    @Synchronized
    fun set(context: Context, password: String) {
        require(password.length >= 8) { "Секретный пароль должен содержать не менее 8 символов." }
        val salt = ByteArray(SALT_LENGTH).also { SecureRandom().nextBytes(it) }
        val verifier = derive(password, salt)
        val serialized = ByteBuffer.allocate(4 + SALT_LENGTH + VERIFIER_LENGTH)
            .putInt(MAGIC)
            .put(salt)
            .put(verifier)
            .array()
        try {
            writeAtomically(credentialFile(context), serialized)
        } finally {
            salt.fill(0)
            verifier.fill(0)
            serialized.fill(0)
        }
    }

    fun verify(context: Context, password: String): Boolean {
        if (password.isEmpty()) return false
        val file = credentialFile(context)
        if (!file.isFile) return false
        val data = runCatching { file.readBytes() }.getOrNull() ?: return false
        if (data.size != 4 + SALT_LENGTH + VERIFIER_LENGTH) return false
        return try {
            val buffer = ByteBuffer.wrap(data)
            if (buffer.int != MAGIC) return false
            val salt = ByteArray(SALT_LENGTH).also(buffer::get)
            val expected = ByteArray(VERIFIER_LENGTH).also(buffer::get)
            val actual = derive(password, salt)
            try {
                MessageDigest.isEqual(expected, actual)
            } finally {
                expected.fill(0)
                actual.fill(0)
                salt.fill(0)
            }
        } catch (_: Exception) {
            false
        } finally {
            data.fill(0)
        }
    }

    @Synchronized
    fun remove(context: Context) {
        val file = credentialFile(context)
        bestEffortOverwrite(file)
        file.delete()
        File(file.parentFile, "$FILE_NAME.tmp").delete()
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
        val temporary = File(destination.parentFile, "$FILE_NAME.tmp")
        FileOutputStream(temporary, false).use { stream ->
            stream.write(bytes)
            stream.fd.sync()
        }
        if (!temporary.renameTo(destination)) {
            FileOutputStream(destination, false).use { stream ->
                stream.write(bytes)
                stream.fd.sync()
            }
            temporary.delete()
        }
    }

    private fun bestEffortOverwrite(file: File) {
        if (!file.isFile) return
        runCatching {
            val originalLength = file.length()
            RandomAccessFile(file, "rw").use { stream ->
                stream.seek(0L)
                val zeros = ByteArray(4096)
                var remaining = originalLength
                while (remaining > 0L) {
                    val count = minOf(zeros.size.toLong(), remaining).toInt()
                    stream.write(zeros, 0, count)
                    remaining -= count.toLong()
                }
                stream.setLength(originalLength)
                stream.fd.sync()
            }
        }
    }
}
