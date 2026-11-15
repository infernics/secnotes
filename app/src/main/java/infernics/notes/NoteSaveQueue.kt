package infernics.notes

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Serial IO queue that keeps a final autosave alive when an editor leaves composition. */
object NoteSaveQueue {
    private val dispatcher = Dispatchers.IO.limitedParallelism(1)
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    fun save(repository: NoteRepository, note: Note, onComplete: (() -> Unit)? = null) {
        scope.launch {
            runCatching { repository.save(note) }
            if (onComplete != null) withContext(Dispatchers.Main) { onComplete() }
        }
    }

    fun delete(repository: NoteRepository, id: String, onComplete: (() -> Unit)? = null) {
        scope.launch {
            runCatching { repository.delete(id) }
            if (onComplete != null) withContext(Dispatchers.Main) { onComplete() }
        }
    }

    fun reorder(repository: NoteRepository, orderedNotes: List<Note>) {
        scope.launch { runCatching { repository.reorder(orderedNotes) } }
    }
}
