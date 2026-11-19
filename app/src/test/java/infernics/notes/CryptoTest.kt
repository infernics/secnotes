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
    fun portableBackupEnvelopeRoundTripsWithItsOwnPassword() {
        val archivePlaintext = ByteArray(700_000) { ((it * 31) % 251).toByte() }
        val backupPassword = "different backup phrase"
        val backupSalt = Crypto.newSalt()
        val backupCrypto = Crypto.fromPassphrase(backupPassword, backupSalt)
        val encryptedBackup = ByteArrayOutputStream()
        encryptedBackup.write("SCNBKUP1".toByteArray(Charsets.US_ASCII))
        encryptedBackup.write(backupSalt)
        backupCrypto.encryptStream(ByteArrayInputStream(archivePlaintext), encryptedBackup)

        val encoded = encryptedBackup.toByteArray()
        val headerSize = 8 + 16
        assertArrayEquals("SCNBKUP1".toByteArray(Charsets.US_ASCII), encoded.copyOfRange(0, 8))
        val importedSalt = encoded.copyOfRange(8, headerSize)
        val importedCrypto = Crypto.fromPassphrase(backupPassword, importedSalt)
        val restored = ByteArrayOutputStream()
        importedCrypto.decryptStream(ByteArrayInputStream(encoded.copyOfRange(headerSize, encoded.size)), restored)
        assertArrayEquals(archivePlaintext, restored.toByteArray())

        val wrongPassword = Crypto.fromPassphrase("another backup phrase", importedSalt)
        try {
            wrongPassword.decryptStream(ByteArrayInputStream(encoded.copyOfRange(headerSize, encoded.size)), ByteArrayOutputStream())
            fail("The backup must not decrypt with a different password")
        } catch (_: Exception) {
            // Expected: GCM authentication must reject a different backup key.
        }
        backupCrypto.destroy()
        importedCrypto.destroy()
        wrongPassword.destroy()
        backupSalt.fill(0)
        importedSalt.fill(0)
        archivePlaintext.fill(0)
    }

    @Test
    fun jpegPayloadSurvivesVaultStreamingEncryption() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val original = ByteArray(384 * 1024) { (it % 251).toByte() }.also {
            it[0] = 0xFF.toByte()
            it[1] = 0xD8.toByte()
            it[it.lastIndex - 1] = 0xFF.toByte()
            it[it.lastIndex] = 0xD9.toByte()
        }
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

    @Test
    fun contextualRecordCannotBeMovedBetweenObjects() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val firstContext = Crypto.contextAad("note-record", "note-one")
        val secondContext = Crypto.contextAad("note-record", "note-two")
        val differentDomain = Crypto.contextAad("file-metadata", "note-one")
        val encrypted = crypto.encrypt("private note", firstContext)
        assertEquals("private note", crypto.decryptToText(encrypted, firstContext))
        try {
            crypto.decryptToText(encrypted, secondContext)
            fail("Ciphertext must not authenticate under a different object ID")
        } catch (_: Exception) {
            // Expected: GCM AAD verification rejects cross-object substitution.
        }
        try {
            crypto.decryptToText(encrypted, differentDomain)
            fail("Ciphertext must not authenticate under a different record domain")
        } catch (_: Exception) {
            // Expected: GCM AAD verification rejects cross-domain substitution.
        } finally {
            firstContext.fill(0)
            secondContext.fill(0)
            differentDomain.fill(0)
            encrypted.fill(0)
        }
    }

    @Test
    fun legacyRecordRemainsReadableForMigration() {
        val crypto = Crypto.fromPassphrase("correct horse battery", Crypto.newSalt())
        val legacy = crypto.encrypt("legacy record")
        val context = Crypto.contextAad("note-record", "legacy-id")
        assertEquals(false, crypto.isContextualRecord(legacy))
        assertEquals("legacy record", crypto.decryptToText(legacy, context))
        context.fill(0)
        legacy.fill(0)
    }

}
