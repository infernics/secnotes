package infernics.notes

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
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

    fun isConfigured(context: Context): Boolean = AtomicFileIO.existsRecoverable(metadataFile(context))

    /** One-time setup. There is deliberately no stored password or biometric wrapper. */
    @Synchronized
    fun configure(context: Context, passphrase: String) {
        val generation = StorageGate.currentGeneration()
        StorageGate.withAccess(generation) { configureInSession(context, passphrase) }
    }

    private fun configureInSession(context: Context, passphrase: String) {
        require(passphrase.isNotEmpty()) { "Введите пароль дополнительного хранилища." }
        val destination = metadataFile(context)
        val parent = destination.parentFile
        check(parent != null && (parent.isDirectory || parent.mkdirs())) {
            "Не удалось подготовить защищённое хранилище приложения."
        }
        // A lone .new file is an uncommitted first-write remnant, not a configured
        // vault. It can be safely discarded because no committed base or legacy backup
        // exists; otherwise AtomicFile must recover the previous record instead.
        val pendingFirstWrite = File(destination.path + ".new")
        if (!AtomicFileIO.existsRecoverable(destination) && pendingFirstWrite.exists()) {
            check(pendingFirstWrite.delete() || !pendingFirstWrite.exists()) {
                "Не удалось очистить незавершённую запись дополнительного хранилища."
            }
        }
        check(!AtomicFileIO.existsRecoverable(destination)) { "Отдельный пароль уже настроен." }
        check(!hiddenDirectory(context).exists()) { "Файловое пространство уже существует; повторная инициализация запрещена." }

        val salt = Crypto.newSalt()
        var record: ByteArray? = null
        try {
            val createdRecord = createRecord(passphrase, salt)
            record = createdRecord
            AtomicFileIO.writeBytes(destination, createdRecord)
            check(hiddenDirectory(context).exists() || hiddenDirectory(context).mkdirs()) {
                "Не удалось создать защищённое файловое пространство."
            }
        } catch (error: Exception) {
            // Do not leave a half-configured store if setup did not commit completely.
            runCatching { overwriteAndDelete(destination) }.onFailure(error::addSuppressed)
            runCatching { overwriteAndDelete(File(destination.parentFile, "$METADATA_NAME.tmp")) }.onFailure(error::addSuppressed)
            runCatching { overwriteAndDelete(File(destination.path + ".new")) }.onFailure(error::addSuppressed)
            runCatching { overwriteAndDelete(File(destination.path + ".bak")) }.onFailure(error::addSuppressed)
            runCatching { overwriteAndDelete(hiddenDirectory(context)) }.onFailure(error::addSuppressed)
            throw error
        } finally {
            salt.fill(0)
            record?.fill(0)
        }
    }

    /**
     * Destroys only the separate file area. A durable marker makes the operation
     * resumable if Android terminates the process during deletion. The primary
     * notes, primary files, primary salt and primary key are never touched here.
     */
    @Synchronized
    fun destroy(context: Context) {
        val marker = wipeMarker(context)
        val parent = marker.parentFile
        check(parent != null && (parent.isDirectory || parent.mkdirs())) {
            "Не удалось начать очистку файлового пространства."
        }
        AtomicFileIO.writeBytes(marker, byteArrayOf(0x53, 0x4E, 0x48, 0x57)) // SNHW
        StorageGate.withExclusiveAccess {
            wipeLocalPayload(context.filesDir, context.cacheDir)
        }
        check(AtomicFileIO.delete(marker)) { "Не удалось завершить очистку файлового пространства." }
    }

    /** Complete an interrupted hidden-area wipe before the unlock UI is shown. */
    @Synchronized
    fun recoverInterruptedWipe(context: Context): Boolean {
        val marker = wipeMarker(context)
        if (!AtomicFileIO.existsRecoverable(marker)) return true
        return runCatching {
            val markerBytes = AtomicFileIO.readBytes(marker)
            try {
                check(markerBytes.contentEquals(byteArrayOf(0x53, 0x4E, 0x48, 0x57))) { "Некорректный маркер очистки скрытого хранилища." }
            } finally {
                markerBytes.fill(0)
            }
            StorageGate.withExclusiveAccess {
                wipeLocalPayload(context.filesDir, context.cacheDir)
            }
            check(AtomicFileIO.delete(marker))
            true
        }.getOrDefault(false)
    }

    /** Pure filesystem helper is exercised by JVM tests to prove primary data is retained. */
    internal fun wipeLocalPayload(filesDirectory: File, cacheDirectory: File) {
        overwriteAndDelete(File(filesDirectory, "$METADATA_NAME.tmp"))
        overwriteAndDelete(File(filesDirectory, METADATA_NAME))
        overwriteAndDelete(File(filesDirectory, "$METADATA_NAME.bak"))
        overwriteAndDelete(File(filesDirectory, "$METADATA_NAME.new"))
        overwriteAndDelete(File(filesDirectory, DIRECTORY_NAME))
        val hiddenCacheFiles = cacheDirectory.listFiles()?.filter { file ->
            file.name.startsWith("media-export-") || file.name.startsWith("media-thumbnail-")
        } ?: error("Не удалось проверить временные файлы скрытого пространства.")
        hiddenCacheFiles.forEach(::overwriteAndDelete)
        check(!File(filesDirectory, METADATA_NAME).exists())
        check(!File(filesDirectory, "$METADATA_NAME.bak").exists())
        check(!File(filesDirectory, "$METADATA_NAME.new").exists())
        check(!File(filesDirectory, DIRECTORY_NAME).exists())
        check(cacheDirectory.listFiles()?.none { file ->
            file.name.startsWith("media-export-") || file.name.startsWith("media-thumbnail-")
        } == true) { "Не удалось удалить временные файлы скрытого пространства." }
    }

    private fun wipeMarker(context: Context) = File(context.noBackupFilesDir, "secnote_hidden_wipe.pending")

    internal fun isValidRecord(record: ByteArray): Boolean {
        val expectedSize = 4 + SALT_LENGTH + 12 + VERIFIER.size + 16
        if (record.size != expectedSize) return false
        return runCatching { ByteBuffer.wrap(record).int == METADATA_MAGIC }.getOrDefault(false)
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
        if (!AtomicFileIO.existsRecoverable(file)) return null
        val record = runCatching { AtomicFileIO.readBytes(file) }.getOrNull() ?: return null
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
        require(passphrase.isNotEmpty())
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
            val children = entry.listFiles()
                ?: error("Не удалось прочитать каталог скрытого хранилища: ${entry.name}")
            children.forEach(::overwriteAndDelete)
            check(entry.delete() || !entry.exists()) { "Не удалось удалить каталог скрытого хранилища: ${entry.name}" }
            check(!entry.exists()) { "Каталог скрытого хранилища остался после удаления: ${entry.name}" }
            return
        }
        runCatching {
            val length = entry.length()
            RandomAccessFile(entry, "rw").use { stream ->
                stream.seek(0L)
                val zeros = ByteArray(4096)
                var remaining = length
                while (remaining > 0) {
                    val count = minOf(zeros.size.toLong(), remaining).toInt()
                    stream.write(zeros, 0, count)
                    remaining -= count
                }
                stream.setLength(length)
                stream.fd.sync()
            }
        }
        check(entry.delete() || !entry.exists()) { "Не удалось удалить файл скрытого хранилища: ${entry.name}" }
        check(!entry.exists()) { "Файл скрытого хранилища остался после удаления: ${entry.name}" }
    }

}
