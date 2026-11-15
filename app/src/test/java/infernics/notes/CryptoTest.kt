package infernics.notes

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CryptoTest {
    @Test
    fun encryptDecryptTextRoundTrip() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = crypto.encrypt("SecNote private note")
        assertEquals("SecNote private note", crypto.decryptToText(encrypted))
    }

    @Test
    fun streamingFileRoundTrip() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val original = ByteArray(512 * 1024) { (it % 251).toByte() }
        val encrypted = ByteArrayOutputStream()
        crypto.encryptStream(ByteArrayInputStream(original), encrypted)

        val decrypted = ByteArrayOutputStream()
        crypto.decryptStream(ByteArrayInputStream(encrypted.toByteArray()), decrypted)
        assertArrayEquals(original, decrypted.toByteArray())
    }

    @Test
    fun tamperedCiphertextIsRejected() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = crypto.encrypt("authenticated content").also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }

        try {
            crypto.decryptToText(encrypted)
            fail("GCM must reject modified ciphertext")
        } catch (_: Exception) {
            // Expected: GCM authentication tag verification failed.
        }
    }

    @Test
    fun tamperedStreamIsRejected() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = ByteArrayOutputStream().also {
            crypto.encryptStream(ByteArrayInputStream(ByteArray(32_000) { it.toByte() }), it)
        }.toByteArray()
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 1).toByte()

        try {
            crypto.decryptStream(ByteArrayInputStream(encrypted), ByteArrayOutputStream())
            fail("GCM must reject a modified file stream")
        } catch (_: Exception) {
            // Expected: GCM authentication tag verification failed.
        }
    }
    @Test
    fun truncatedStreamIsRejected() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = ByteArrayOutputStream().also {
            crypto.encryptStream(ByteArrayInputStream(ByteArray(150_000) { (it % 239).toByte() }), it)
        }.toByteArray()
        val truncated = encrypted.copyOf(encrypted.size - 1)

        try {
            crypto.decryptStream(ByteArrayInputStream(truncated), ByteArrayOutputStream())
            fail("Truncated encrypted stream must be rejected")
        } catch (_: Exception) {
            // Expected: missing/invalid authenticated footer.
        }
    }

    @Test
    fun destroyedContentKeyCannotBeUsedAgain() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val encrypted = crypto.encrypt("private")
        assertEquals("private", crypto.decryptToText(encrypted))

        crypto.destroy()
        try {
            crypto.decryptToText(encrypted)
            fail("A destroyed in-memory content key must not decrypt data")
        } catch (_: Exception) {
            // Expected: key material was cleared.
        }
    }

    @Test
    fun emergencyDestroyClearsEveryLiveSessionKey() {
        val first = Crypto.fromRawKeyBytes(ByteArray(32) { 0x11 })
        val second = Crypto.fromRawKeyBytes(ByteArray(32) { 0x22 })
        val firstBlob = first.encrypt("primary")
        val secondBlob = second.encrypt("hidden")

        Crypto.destroyAll()

        try {
            first.decryptToText(firstBlob)
            fail("Emergency cleanup must destroy the primary content key")
        } catch (_: Exception) { }
        try {
            second.decryptToText(secondBlob)
            fail("Emergency cleanup must destroy the hidden content key")
        } catch (_: Exception) { }
    }

}
