package infernics.notes

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.security.KeyStore
import java.util.Collections

/**
 * Resumable emergency cleanup.
 * A durable marker is written before cleanup starts. If Android kills the process,
 * SecNote detects the marker on the next launch and continues cleanup before showing
 * either the unlock screen or the first-run screen.
 *
 * The app best-effort overwrites app-owned files and deletes them. Android flash storage
 * and storage controllers can retain old physical blocks, so physical forensic erasure
 * cannot be guaranteed by an ordinary app. Losing the vault password salt and encrypted
 * verifier also prevents the app from deriving the old content key.
 */
object EmergencyWipe {
    private const val MARKER = "secnote_emergency_wipe.pending"
    private const val SHARED_PREFS = "shared_prefs"
    private const val KEYSTORE_ALIAS_PREFIX = "SecNote"

    fun isPending(context: Context): Boolean = markerFile(context).isFile

    @Synchronized
    fun markPending(context: Context) {
        val marker = markerFile(context)
        marker.parentFile?.mkdirs()
        FileOutputStream(marker, false).use { stream ->
            stream.write("SECNOTE-WIPE-V1".toByteArray(Charsets.US_ASCII))
            stream.fd.sync()
        }
    }

    /** Returns true only after all app-owned storage targets are cleared and marker removed. */
    @Synchronized
    fun complete(context: Context): Boolean {
        if (!isPending(context)) markPending(context)
        return try {
            // Block and drain every in-flight note/file operation before deleting app data.
            // Existing repository instances are invalidated by StorageGate's generation.
            StorageGate.blockAndDrain()
            // Wipe reachable in-memory content keys after all repository operations finish.
            Crypto.destroyAll()

            // Clear in-memory and on-disk preference caches, then revoke device-bound keys.
            // This matters because deleting SharedPreferences files directly does not clear
            // Android's process-local SharedPreferences cache.
            AppPreferences.reset(context)
            BiometricVault.disable(context)
            if (!deleteSecNoteKeyStoreAliases()) return false

            // Invalidate the current password-derived key material before wiping payloads.
            val criticalMaterialsClean = listOf(
                "key.salt", "key.check", "panic.credential", "key.salt.tmp", "key.check.tmp"
            ).all { name -> wipeEntry(File(context.filesDir, name)) }
            if (!criticalMaterialsClean) return false

            val targets = buildList {
                add(context.filesDir)
                add(context.cacheDir)
                add(context.codeCacheDir)
                add(File(context.applicationInfo.dataDir, SHARED_PREFS))
                add(File(context.applicationInfo.dataDir, "databases"))
                add(File(context.applicationInfo.dataDir, "app_webview"))
                add(File(context.applicationInfo.dataDir, "app_textures"))
            }.distinctBy { it.absolutePath }

            for (directory in targets) {
                if (directory.exists() && !wipeDirectoryContents(directory)) return false
            }

            // Keep the durable marker until the very last step. Clear all other no-backup
            // data, but preserve the marker itself so interrupted cleanup is resumable.
            val noBackup = context.noBackupFilesDir
            val marker = markerFile(context)
            if (noBackup.exists() && !wipeDirectoryContents(noBackup, setOf(marker.canonicalPath))) {
                return false
            }

            // Verify the password material and app-private data are no longer present.
            if (File(context.filesDir, "key.salt").exists()) return false
            if (File(context.filesDir, "key.check").exists()) return false
            if (File(context.filesDir, "panic.credential").exists()) return false
            if (File(context.filesDir, "notes").exists()) return false
            if (File(context.filesDir, "file_vault").exists()) return false

            marker.delete()
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

    private fun markerFile(context: Context) = File(context.noBackupFilesDir, MARKER)

    private fun wipeDirectoryContents(directory: File, preserved: Set<String> = emptySet()): Boolean {
        if (!directory.exists()) return true
        val children = directory.listFiles() ?: return false
        var success = true
        for (child in children) {
            val canonical = runCatching { child.canonicalPath }.getOrNull()
            if (canonical != null && canonical in preserved) continue
            if (!wipeEntry(child)) success = false
        }
        return success && directory.listFiles()?.all {
            runCatching { it.canonicalPath in preserved }.getOrDefault(false)
        } == true
    }

    private fun wipeEntry(entry: File): Boolean {
        if (entry.isDirectory) {
            val children = entry.listFiles() ?: return false
            var success = true
            for (child in children) if (!wipeEntry(child)) success = false
            return success && entry.delete()
        }
        bestEffortOverwrite(entry)
        return !entry.exists() || entry.delete()
    }

    private fun bestEffortOverwrite(file: File) {
        if (!file.isFile) return
        runCatching {
            val originalLength = file.length()
            RandomAccessFile(file, "rw").use { stream ->
                stream.seek(0L)
                val zeros = ByteArray(64 * 1024)
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
