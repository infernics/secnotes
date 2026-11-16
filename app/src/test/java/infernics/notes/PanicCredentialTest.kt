package infernics.notes

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PanicCredentialTest {
    @Test
    fun verifierAcceptsOnlyTheConfiguredSecret() {
        val salt = ByteArray(16) { index -> (index * 7 + 3).toByte() }
        val record = PanicCredential.createRecord("emergency-code-42", salt)

        assertTrue(PanicCredential.verifyRecord("emergency-code-42", record))
        assertFalse(PanicCredential.verifyRecord("another-password", record))
    }

    @Test
    fun verifierRejectsMalformedOrTruncatedRecords() {
        val salt = ByteArray(16) { it.toByte() }
        val record = PanicCredential.createRecord("emergency-code-42", salt)

        assertFalse(PanicCredential.verifyRecord("emergency-code-42", record.copyOf(record.size - 1)))
        val modified = record.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(PanicCredential.verifyRecord("emergency-code-42", modified))
    }
    @Test
    fun acceptsASingleCharacterSecretAndRejectsOnlyEmptyInput() {
        val salt = ByteArray(16) { (it + 1).toByte() }
        val record = PanicCredential.createRecord("x", salt)
        assertTrue(PanicCredential.verifyRecord("x", record))
        assertFalse(PanicCredential.verifyRecord("", record))
    }

    @Test(expected = IllegalArgumentException::class)
    fun doesNotAllowAnEmptyEmergencySecret() {
        PanicCredential.createRecord("", ByteArray(16))
    }

}
