package infernics.notes

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

class HiddenVaultTest {
    @Test
    fun independentPassphraseUnlocksOnlyItsOwnVerifier() {
        val password = "separate-secret-phrase-2026"
        val salt = ByteArray(16) { index -> (index * 11 + 5).toByte() }
        val record = HiddenVault.createRecord(password, salt)

        val unlocked = HiddenVault.unlockFromRecord(password, record)
        assertNotNull(unlocked)
        unlocked!!.destroy()

        assertNull(HiddenVault.unlockFromRecord("some-other-hidden-password", record))
    }

    @Test
    fun persistedVerifierDoesNotContainThePassphrase() {
        val password = "never-store-this-hidden-passphrase-2026"
        val salt = ByteArray(16) { (it * 7 + 3).toByte() }
        val record = HiddenVault.createRecord(password, salt)
        val serialized = String(record, Charsets.ISO_8859_1)
        assertFalse(serialized.contains(password))
        assertTrue(record.size > 16 + 4)
    }

    @Test
    fun malformedOrTamperedHiddenVerifierIsRejected() {
        val salt = ByteArray(16) { it.toByte() }
        val record = HiddenVault.createRecord("long-hidden-password-123", salt)

        assertNull(HiddenVault.unlockFromRecord("long-hidden-password-123", record.copyOf(record.size - 1)))
        val modified = record.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertNull(HiddenVault.unlockFromRecord("long-hidden-password-123", modified))
    }
}
