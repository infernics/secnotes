package infernics.notes

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
import java.io.FileOutputStream
import java.security.KeyStore
import java.util.Collections

/**
 * Resumable emergency cleanup of SecNote-owned local data.
 *
 * A durable marker is written before the lockout notice is shown. If Android terminates
 * the process or the device restarts during cleanup, the marker causes cleanup to resume
 * before either the unlock or first-run screen is displayed.
 *
 * File overwrite is best effort only. Android flash translation layers and storage
 * providers do not let an ordinary app promise physical forensic erasure of old blocks.
 * Removing the password salt/verifier and all SecNote Keystore aliases makes the old
 * encrypted vault inaccessible to SecNote even if a stale ciphertext block remains.
 */
object EmergencyWipe {
    private const val MARKER = "secnote_emergency_wipe.pending"
    private const val KEYSTORE_ALIAS_PREFIX = "SecNote"

    fun isPending(context: Context): Boolean = markerFile(context).isFile

    @Synchronized
    fun markPending(context: Context) {
        val marker = markerFile(context)
        check(marker.parentFile?.let { it.exists() || it.mkdirs() } == true) {
            "Не удалось создать защищённый маркер очистки."
        }
        FileOutputStream(marker, false).use { stream ->
            stream.write("SECNOTE-WIPE-V1".toByteArray(Charsets.US_ASCII))
            stream.flush()
            stream.fd.sync()
        }
        check(marker.isFile && marker.length() > 0L) {
            "Не удалось сохранить маркер очистки."
        }
    }

    /** Returns true only when all app-owned targets are cleared and the marker is removed. */
    @Synchronized
    fun complete(context: Context): Boolean {
        if (!isPending(context)) markPending(context)

        return try {
            // Disable the app's biometric preference and key before removing other data.
            BiometricVault.disable(context)
            if (!deleteSecNoteKeyStoreAliases()) return false

            // Invalidate the old vault password and panic verifier first.
            val criticalFiles = listOf(
                "key.salt",
                "key.check",
                "panic.credential",
                "key.salt.tmp",
                "key.check.tmp",
                "panic.credential.tmp"
            )
            for (name in criticalFiles) {
                if (!wipeEntry(File(context.filesDir, name))) return false
            }

            // These are all app-private or app-specific directories. Include secondary
            // external volumes, while leaving user-owned Documents/Downloads untouched.
            val targets = buildList {
                add(context.filesDir)
                add(context.cacheDir)
                add(context.codeCacheDir)
                addAll(context.externalCacheDirs.filterNotNull())
                addAll(context.getExternalFilesDirs(null).filterNotNull())
                addAll(context.externalMediaDirs.filterNotNull())
                add(File(context.applicationInfo.dataDir, "shared_prefs"))
                add(File(context.applicationInfo.dataDir, "databases"))
                add(File(context.applicationInfo.dataDir, "app_webview"))
            }.distinctBy { directory ->
                runCatching { directory.canonicalPath }.getOrElse { directory.absolutePath }
            }

            for (directory in targets) {
                if (directory.exists() && !wipeDirectoryContents(directory)) return false
            }

            // Preserve the marker itself until the final operation so interrupted cleanup
            // can always resume. Other no-backup files are SecNote-owned and are removed.
            val marker = markerFile(context)
            val preserved = setOf(marker.canonicalPath)
            val noBackup = context.noBackupFilesDir
            if (noBackup.exists() && !wipeDirectoryContents(noBackup, preserved)) return false

            // Verify that vault payload directories and key material are gone.
            val mustBeAbsent = listOf(
                File(context.filesDir, "key.salt"),
                File(context.filesDir, "key.check"),
                File(context.filesDir, "panic.credential"),
                File(context.filesDir, "notes"),
                File(context.filesDir, "file_vault")
            )
            if (mustBeAbsent.any { it.exists() }) return false

            val deleted = marker.delete() || !marker.exists()
            deleted && !marker.exists()
        } catch (_: Exception) {
            false
        }
    }

    private fun deleteSecNoteKeyStoreAliases(): Boolean = runCatching {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val aliases = Collections.list(store.aliases())
            .filter { it.startsWith(KEYSTORE_ALIAS_PREFIX, ignoreCase = true) }
        aliases.forEach { alias -> store.deleteEntry(alias) }
        aliases.none { store.containsAlias(it) }
    }.getOrDefault(false)

    private fun markerFile(context: Context) =
        File(context.noBackupFilesDir, MARKER)

    private fun wipeDirectoryContents(directory: File, preserved: Set<String> = emptySet()): Boolean {
        if (!directory.exists()) return true
        val children = directory.listFiles() ?: return false
        var success = true
        for (child in children) {
            val canonical = runCatching { child.canonicalPath }.getOrNull()
            if (canonical != null && canonical in preserved) continue
            if (!wipeEntry(child)) success = false
        }
        return success && directory.listFiles()?.all { child ->
            runCatching { child.canonicalPath in preserved }.getOrDefault(false)
        } == true
    }

    private fun wipeEntry(entry: File): Boolean {
        if (!entry.exists()) return true
        if (entry.isDirectory) {
            val children = entry.listFiles() ?: return false
            var success = true
            for (child in children) if (!wipeEntry(child)) success = false
            if (!success) return false
            return entry.delete() || !entry.exists()
        }
        bestEffortOverwrite(entry)
        return entry.delete() || !entry.exists()
    }

    private fun bestEffortOverwrite(file: File) {
        if (!file.isFile) return
        runCatching {
            val originalLength = file.length()
            RandomAccessFile(file, "rw").use { random ->
                random.seek(0L)
                val zeros = ByteArray(64 * 1024)
                var remaining = originalLength
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
