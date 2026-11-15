package infernics.notes

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.system.Os
import android.system.OsConstants
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.util.UUID

data class VaultFile(
    val id: String,
    val name: String,
    val mimeType: String,
    val sizeBytes: Long,
    val addedAt: Long
)

data class VaultImportResult(
    val file: VaultFile,
    val originalOverwritten: Boolean,
    val originalDeleted: Boolean
)

data class BatchExportResult(
    val exported: Int,
    val failedNames: List<String>
)

data class BatchImportResult(
    val imported: Int,
    val originalsOverwritten: Int,
    val originalsDeleted: Int,
    val failedNames: List<String>
)

/**
 * Independent encrypted file area. Each file has its own authenticated content stream
 * and encrypted metadata. Plaintext is written only to short-lived private cache files
 * during thumbnailing/export, then removed.
 */
class FileVaultRepository(
    private val context: Context,
    private val crypto: Crypto
) {
    private val generation = StorageGate.currentGeneration()
    private val root = StorageGate.withAccess(generation) {
        File(context.filesDir, "file_vault").apply { mkdirs() }
    }

    init {
        StorageGate.withAccess(generation) {
            // Remove leftovers from interrupted imports/exports. Cache files may contain
            // short-lived plaintext, so use best-effort overwrite before deleting them.
            root.listFiles { file -> file.name.endsWith(".tmp") }?.forEach(::overwriteAndDelete)
            context.cacheDir.listFiles { file ->
                file.name.startsWith("secnote-export-") || file.name.startsWith("secnote-thumbnail-")
            }?.forEach(::overwriteAndDelete)
            cleanupOrphans()
        }
    }

    fun loadAll(): List<VaultFile> = StorageGate.withAccess(generation) {
        root.listFiles { file -> file.name.endsWith(".data.enc") }
            .orEmpty()
            .mapNotNull { dataFile ->
                val id = dataFile.name.removeSuffix(".data.enc")
                runCatching { readMetadata(id) }.getOrNull()
            }
            .sortedByDescending { it.addedAt }
    }

    /**
     * Encrypt the selected source first. Only after the encrypted data and metadata
     * are safely committed do we make a best-effort attempt to overwrite and delete
     * the original document. Physical erasure cannot be guaranteed on flash storage
     * or by third-party document providers.
     */
    fun importAndRemoveOriginal(uri: Uri): VaultImportResult = StorageGate.withAccess(generation) {
        val item = importEncryptedCopy(uri)
        val overwritten = bestEffortOverwriteSource(uri)
        val deleted = bestEffortDeleteSource(uri)
        VaultImportResult(item, overwritten, deleted)
    }

    /**
     * Import multiple SAF documents sequentially. Each source is encrypted and
     * committed independently before its original is touched. One failed provider
     * does not prevent the remaining selected files from being imported.
     */
    fun importManyAndRemoveOriginal(uris: Collection<Uri>): BatchImportResult {
        var imported = 0
        var overwritten = 0
        var deleted = 0
        val failedNames = mutableListOf<String>()
        uris.distinctBy { it.toString() }.forEach { uri ->
            val displayName = queryDisplayName(uri).ifBlank { "Выбранный файл" }
            runCatching { importAndRemoveOriginal(uri) }
                .onSuccess { result ->
                    imported++
                    if (result.originalOverwritten) overwritten++
                    if (result.originalDeleted) deleted++
                }
                .onFailure {
                    failedNames += displayName.take(120)
                }
        }
        return BatchImportResult(
            imported = imported,
            originalsOverwritten = overwritten,
            originalsDeleted = deleted,
            failedNames = failedNames
        )
    }

    private fun importEncryptedCopy(uri: Uri): VaultFile {
        val displayName = queryDisplayName(uri).ifBlank { "Файл_${System.currentTimeMillis()}" }
        val name = displayName.substringAfterLast('/').substringAfterLast('\\').take(180)
        val mime = context.contentResolver.getType(uri) ?: "application/octet-stream"
        val id = UUID.randomUUID().toString()
        val dataTemp = File(root, "$id.data.tmp")
        val metaTemp = File(root, "$id.meta.tmp")
        val dataTarget = dataFile(id)
        val metaTarget = metadataFile(id)

        try {
            val input = context.contentResolver.openInputStream(uri)
                ?: error("Не удалось открыть выбранный файл")
            val size = input.use { source ->
                FileOutputStream(dataTemp, false).use { encryptedOutput ->
                    val encryptedSize = crypto.encryptStream(source, encryptedOutput)
                    encryptedOutput.fd.sync()
                    encryptedSize
                }
            }
            val item = VaultFile(
                id = id,
                name = name,
                mimeType = mime,
                sizeBytes = size,
                addedAt = System.currentTimeMillis()
            )
            val encryptedMetadata = crypto.encrypt(metadataJson(item))
            try {
                FileOutputStream(metaTemp, false).use { metadataOutput ->
                    metadataOutput.write(encryptedMetadata)
                    metadataOutput.fd.sync()
                }
            } finally {
                encryptedMetadata.fill(0)
            }
            check(dataTemp.renameTo(dataTarget)) { "Не удалось сохранить зашифрованный файл" }
            check(metaTemp.renameTo(metaTarget)) { "Не удалось сохранить метаданные файла" }
            return item
        } catch (error: Exception) {
            // A failed import may leave partial ciphertext. Remove it using the same
            // best-effort overwrite path as a normal vault deletion.
            overwriteAndDelete(dataTemp)
            overwriteAndDelete(metaTemp)
            overwriteAndDelete(dataTarget)
            overwriteAndDelete(metaTarget)
            throw error
        }
    }

    /**
     * Best effort only: request a seekable read/write descriptor, overwrite its
     * original length with zeroes, and fsync. SAF providers can reject write access
     * or expose non-seekable/cloud-backed streams. Flash translation layers can also
     * retain old physical blocks, so this is not a certified secure erase.
     */
    private fun bestEffortOverwriteSource(uri: Uri): Boolean {
        val size = querySize(uri)
        val descriptor = try {
            context.contentResolver.openFileDescriptor(uri, "rw") ?: return false
        } catch (_: Exception) {
            return false
        }

        return try {
            descriptor.use { pfd ->
                val actualSize = size ?: pfd.statSize.takeIf { it >= 0L } ?: return false
                Os.lseek(pfd.fileDescriptor, 0L, OsConstants.SEEK_SET)
                val zeros = ByteArray(64 * 1024)
                var remaining = actualSize
                while (remaining > 0L) {
                    val count = minOf(zeros.size.toLong(), remaining).toInt()
                    var offset = 0
                    while (offset < count) {
                        val written = Os.write(pfd.fileDescriptor, zeros, offset, count - offset)
                        check(written > 0) { "Не удалось перезаписать исходный файл" }
                        offset += written
                    }
                    remaining -= count.toLong()
                }
                Os.fsync(pfd.fileDescriptor)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun bestEffortDeleteSource(uri: Uri): Boolean {
        val documentDelete = runCatching {
            if (DocumentsContract.isDocumentUri(context, uri)) {
                DocumentsContract.deleteDocument(context.contentResolver, uri)
            } else false
        }.getOrDefault(false)
        if (documentDelete) return true
        return runCatching { context.contentResolver.delete(uri, null, null) > 0 }
            .getOrDefault(false)
    }

    /** Export exactly one vault item to a caller-selected document URI. */
    fun export(id: String, destination: Uri) = StorageGate.withAccess(generation) {
        val item = readMetadata(id)
        exportVerified(item, destination)
    }

    /**
     * Decrypt a selected batch into a user-selected SAF folder. Each item is
     * authenticated into a private temporary file before any plaintext is copied
     * to its destination. Individual failures do not abort the remaining exports.
     */
    fun exportManyToTree(ids: Collection<String>, treeUri: Uri): BatchExportResult = StorageGate.withAccess(generation) {
        var exported = 0
        val failures = mutableListOf<String>()
        val treeDocumentUri = runCatching {
            DocumentsContract.buildDocumentUriUsingTree(
                treeUri,
                DocumentsContract.getTreeDocumentId(treeUri)
            )
        }.getOrElse { treeUri }
        ids.distinct().forEach { id ->
            var createdUri: Uri? = null
            val item = runCatching { readMetadata(id) }.getOrElse {
                failures += "Файл ($id)"
                return@forEach
            }
            try {
                createdUri = DocumentsContract.createDocument(
                    context.contentResolver,
                    treeDocumentUri,
                    item.mimeType.ifBlank { "application/octet-stream" },
                    safeDocumentName(item.name)
                ) ?: error("Провайдер не создал файл")
                exportVerified(item, createdUri)
                exported++
            } catch (_: Exception) {
                createdUri?.let { runCatching { DocumentsContract.deleteDocument(context.contentResolver, it) } }
                failures += item.name
            }
        }
        BatchExportResult(exported, failures)
    }

    fun delete(id: String) = StorageGate.withAccess(generation) {
        overwriteAndDelete(dataFile(id))
        overwriteAndDelete(metadataFile(id))
    }

    fun deleteMany(ids: Collection<String>): Int = StorageGate.withAccess(generation) {
        var removed = 0
        ids.distinct().forEach { id ->
            val existed = dataFile(id).exists() || metadataFile(id).exists()
            delete(id)
            if (existed && !dataFile(id).exists() && !metadataFile(id).exists()) removed++
        }
        removed
    }

    /** Decrypt into a private temp file, then stream the verified data to the destination. */
    private fun exportVerified(item: VaultFile, destination: Uri) {
        val verifiedPlaintext = File.createTempFile("secnote-export-", ".tmp", context.cacheDir)
        try {
            dataFile(item.id).inputStream().use { encryptedInput ->
                verifiedPlaintext.outputStream().use { temporaryOutput ->
                    crypto.decryptStream(encryptedInput, temporaryOutput)
                }
            }
            val destinationOutput = context.contentResolver.openOutputStream(destination, "w")
                ?: error("Не удалось создать файл для экспорта")
            verifiedPlaintext.inputStream().use { source ->
                destinationOutput.use { target -> source.copyTo(target) }
            }
        } finally {
            overwriteAndDelete(verifiedPlaintext)
        }
    }

    /**
     * Decrypt an image to private cache, decode a bounded bitmap and delete the
     * plaintext temp file immediately afterwards.
     */
    fun loadThumbnail(id: String, maxDimension: Int = 420): Bitmap? = StorageGate.withAccess(generation) {
        require(maxDimension in 64..2048) { "Invalid thumbnail dimension" }
        val temporaryPlaintext = File.createTempFile("secnote-thumbnail-", ".tmp", context.cacheDir)
        try {
            readMetadata(id)
            dataFile(id).inputStream().use { encryptedInput ->
                temporaryPlaintext.outputStream().use { output ->
                    crypto.decryptStream(encryptedInput, output)
                }
            }
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(temporaryPlaintext.absolutePath, bounds)
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return@withAccess null
            var sampleSize = 1
            while (maxOf(bounds.outWidth / sampleSize, bounds.outHeight / sampleSize) > maxDimension) {
                sampleSize *= 2
            }
            val options = BitmapFactory.Options().apply {
                inSampleSize = sampleSize
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
            BitmapFactory.decodeFile(temporaryPlaintext.absolutePath, options)
        } catch (_: Exception) {
            null
        } finally {
            overwriteAndDelete(temporaryPlaintext)
        }
    }

    private fun readMetadata(id: String): VaultFile {
        val json = JSONObject(crypto.decryptToText(metadataFile(id).readBytes()))
        return VaultFile(
            id = id,
            name = json.getString("name"),
            mimeType = json.optString("mimeType", "application/octet-stream"),
            sizeBytes = json.optLong("sizeBytes", 0L),
            addedAt = json.optLong("addedAt", 0L)
        )
    }

    private fun metadataJson(item: VaultFile): String = JSONObject()
        .put("name", item.name)
        .put("mimeType", item.mimeType)
        .put("sizeBytes", item.sizeBytes)
        .put("addedAt", item.addedAt)
        .toString()

    private fun overwriteAndDelete(file: File) {
        if (!file.exists()) return
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
        file.delete()
    }

    private fun dataFile(id: String) = File(root, "$id.data.enc")
    private fun metadataFile(id: String) = File(root, "$id.meta.enc")

    private fun queryDisplayName(uri: Uri): String = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (index >= 0) cursor.getString(index).orEmpty() else ""
                } else ""
            }.orEmpty()
    }.getOrDefault("")

    private fun querySize(uri: Uri): Long? = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (index >= 0 && !cursor.isNull(index)) cursor.getLong(index) else null
                } else null
            }
    }.getOrNull()?.takeIf { it >= 0L }

    private fun safeDocumentName(value: String): String =
        value.substringAfterLast('/').substringAfterLast('\\').replace(Regex("[\\r\\n]"), "_").take(180)

    private fun cleanupOrphans() {
        val files = root.listFiles().orEmpty()
        val dataIds = files.filter { it.name.endsWith(".data.enc") }
            .map { it.name.removeSuffix(".data.enc") }.toSet()
        val metadataIds = files.filter { it.name.endsWith(".meta.enc") }
            .map { it.name.removeSuffix(".meta.enc") }.toSet()
        (dataIds - metadataIds).forEach { overwriteAndDelete(dataFile(it)) }
        (metadataIds - dataIds).forEach { overwriteAndDelete(metadataFile(it)) }
    }
}
