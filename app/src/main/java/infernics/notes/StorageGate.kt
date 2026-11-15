package infernics.notes

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * Coordinates all note/file-vault operations with the emergency wipe.
 *
 * Every repository instance captures a generation. Beginning an emergency wipe blocks
 * new operations, waits for in-flight operations to finish, and advances the generation.
 * Old repository instances therefore remain invalid even after a fresh vault is created.
 */
object StorageGate {
    private val lock = ReentrantReadWriteLock(true)
    private val accessDepth = ThreadLocal.withInitial { 0 }
    @Volatile private var blocked = false
    @Volatile private var generation = 0L

    fun currentGeneration(): Long = lock.read {
        check(!blocked) { "Локальное хранилище заблокировано для очистки" }
        generation
    }

    fun <T> withAccess(expectedGeneration: Long, action: () -> T): T {
        val readLock = lock.readLock()
        readLock.lock()
        val previousDepth = accessDepth.get()
        try {
            // An operation already holding the read lock may make nested repository calls
            // while a writer is waiting. New readers are rejected once blocked is set.
            check(!blocked || previousDepth > 0) { "Локальное хранилище очищается" }
            check(expectedGeneration == generation) { "Эта сессия хранилища уже недействительна" }
            accessDepth.set(previousDepth + 1)
            return action()
        } finally {
            accessDepth.set(previousDepth)
            readLock.unlock()
        }
    }

    /** Runs a consistent multi-file operation while excluding every repository read/write.
     * Unlike blockAndDrain, this does not advance the session generation.
     */
    fun <T> withExclusiveAccess(action: () -> T): T {
        val writeLock = lock.writeLock()
        writeLock.lock()
        try {
            check(!blocked) { "Локальное хранилище заблокировано для очистки" }
            return action()
        } finally {
            writeLock.unlock()
        }
    }

    /** Blocks new accesses and waits until every active repository operation has exited. */
    fun blockAndDrain() {
        blocked = true
        lock.write {
            generation += 1L
        }
    }

    /** Called after a locked existing vault has been authenticated again. */
    fun resumeAfterUnlock() {
        lock.write {
            blocked = false
        }
    }

    /** Called only after a completely new vault has been created successfully. */
    fun resumeAfterNewVault() = resumeAfterUnlock()

    fun isBlocked(): Boolean = blocked
}
