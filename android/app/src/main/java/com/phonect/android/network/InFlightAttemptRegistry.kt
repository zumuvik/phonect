package com.phonect.android.network

import java.io.Closeable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Owns one cancellable connection attempt per discovery key. */
internal class InFlightAttemptRegistry<K>(private val onCleared: (K) -> Unit = {}) {
    internal class Attempt<K> internal constructor(
        internal val key: K,
        internal val owner: Job,
    ) {
        internal var socket: Closeable? = null
        internal var cancelling: Boolean = false
    }

    private val attempts = mutableMapOf<K, Attempt<K>>()

    fun claim(scope: CoroutineScope, key: K, work: suspend (Attempt<K>) -> Unit): Attempt<K>? = synchronized(this) {
        if (attempts.containsKey(key)) return null
        lateinit var attempt: Attempt<K>
        val owner = scope.launch(start = CoroutineStart.LAZY) {
            work(attempt)
        }
        attempt = Attempt(key, owner)
        attempts[key] = attempt
        owner.invokeOnCompletion { complete(attempt) }
        attempt
    }

    fun start(attempt: Attempt<K>) = attempt.owner.start()

    fun attachSocket(attempt: Attempt<K>, socket: Closeable) {
        val rejected = synchronized(this) {
            if (attempts[attempt.key] !== attempt || attempt.cancelling || attempt.owner.isCancelled) true else {
                attempt.socket = socket
                false
            }
        }
        if (rejected) closeQuietly(socket)
    }

    fun complete(attempt: Attempt<K>) {
        val removed = synchronized(this) {
            val isCurrent = attempts[attempt.key] === attempt && !attempt.cancelling
            if (isCurrent) attempts.remove(attempt.key)
            val socket = attempt.socket
            attempt.socket = null
            socket?.let(::closeQuietly)
            isCurrent
        }
        if (removed) onCleared(attempt.key)
    }

    fun cancelAll() {
        val cancelled = synchronized(this) {
            attempts.values.map { attempt ->
                attempt.cancelling = true
                attempt to attempt.socket.also { attempt.socket = null }
            }
        }
        cancelled.forEach { (attempt, socket) ->
            attempt.owner.cancel()
            socket?.let(::closeQuietly)
        }
        val cleared = synchronized(this) {
            cancelled.mapNotNull { (attempt, _) ->
                if (attempts[attempt.key] === attempt) {
                    attempts.remove(attempt.key)
                    attempt.key
                } else null
            }
        }
        cleared.forEach(onCleared)
    }

    private fun closeQuietly(socket: Closeable) {
        try { socket.close() } catch (_: Exception) { }
    }
}
