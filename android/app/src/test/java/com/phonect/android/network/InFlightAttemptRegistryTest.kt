package com.phonect.android.network

import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class InFlightAttemptRegistryTest {
    private val dispatcher = StandardTestDispatcher()

    @Test fun concurrentClaimHasExactlyOneWinner() {
        val registry = InFlightAttemptRegistry<String>()
        val scope = CoroutineScope(SupervisorJob())
        val gate = CountDownLatch(1); val winners = AtomicInteger()
        val threads = List(8) { Thread {
            gate.await()
            if (registry.claim(scope, "pc") { } != null) winners.incrementAndGet()
        } }
        threads.forEach(Thread::start); gate.countDown(); threads.forEach(Thread::join)
        assertEquals(1, winners.get()); registry.cancelAll(); scope.cancel()
    }

    @Test fun successAndExceptionReleaseForRetry() = runTest(dispatcher) {
        val registry = InFlightAttemptRegistry<String>()
        registry.claim(this, "success") { }!!.also(registry::start); runCurrent()
        assertNotNull(registry.claim(this, "success") { })
        registry.cancelAll()
        val failure = AtomicReference<Throwable?>()
        val handler = CoroutineExceptionHandler { _, error -> failure.set(error) }
        val failureScope = CoroutineScope(SupervisorJob() + dispatcher + handler)
        registry.claim(failureScope, "failure") { error("expected") }!!.also(registry::start)
        runCurrent()
        assertEquals("expected", failure.get()?.message)
        failureScope.cancel()
        assertNotNull(registry.claim(this, "failure") { }); registry.cancelAll()
    }

    @Test fun cancellationAfterStartAndBeforeStartReleaseForRetry() = runTest(dispatcher) {
        val registry = InFlightAttemptRegistry<String>()
        val started = registry.claim(this, "started") { kotlinx.coroutines.awaitCancellation() }!!
        registry.start(started); runCurrent(); started.owner.cancel(); runCurrent()
        assertNotNull(registry.claim(this, "started") { }); registry.cancelAll()
        val lazy = registry.claim(this, "lazy") { }!!
        lazy.owner.cancel()
        assertNotNull(registry.claim(this, "lazy") { }); registry.cancelAll()
    }

    @Test fun alreadyCancelledParentReleasesLazyClaim() = runTest(dispatcher) {
        val registry = InFlightAttemptRegistry<String>()
        val parent = SupervisorJob().also { it.cancel() }
        val scope = CoroutineScope(parent + dispatcher)
        registry.claim(scope, "cancelled") { }!!
        assertNotNull(registry.claim(this, "cancelled") { })
        registry.cancelAll(); scope.cancel()
    }

    @Test fun socketsAndStaleCompletionAreSafe() = runTest(dispatcher) {
        val registry = InFlightAttemptRegistry<String>()
        val first = registry.claim(this, "pc") { }!!
        val attached = FlagCloseable(); registry.attachSocket(first, attached)
        first.owner.cancel(); assertTrue(attached.closed)
        val replacement = registry.claim(this, "pc") { }!!
        registry.complete(first)
        assertNull(registry.claim(this, "pc") { })
        val late = FlagCloseable(); registry.attachSocket(first, late); assertTrue(late.closed)
        replacement.owner.cancel(); runCurrent()
        assertNotNull(registry.claim(this, "pc") { }); registry.cancelAll()
    }

    @Test fun throwingCloseDoesNotBlockCancelAllAndIsIdempotent() = runTest(dispatcher) {
        val registry = InFlightAttemptRegistry<String>()
        val bad = registry.claim(this, "bad") { }!!
        val good = registry.claim(this, "good") { }!!
        val closed = FlagCloseable(); registry.attachSocket(bad, ThrowingCloseable()); registry.attachSocket(good, closed)
        registry.cancelAll(); registry.cancelAll()
        assertTrue(closed.closed)
        assertNotNull(registry.claim(this, "bad") { }); assertNotNull(registry.claim(this, "good") { }); registry.cancelAll()
    }

    @Test fun cancelAllKeepsKeyClaimedUntilOwnerIsCancelled() = runTest(dispatcher) {
        val registry = InFlightAttemptRegistry<String>()
        val owner = registry.claim(this, "pc") { kotlinx.coroutines.awaitCancellation() }!!
        registry.start(owner); runCurrent()
        val admittedDuringCancellation = AtomicInteger()
        owner.owner.invokeOnCompletion {
            if (registry.claim(this, "pc") { } != null) admittedDuringCancellation.incrementAndGet()
        }
        registry.cancelAll()
        assertTrue(owner.owner.isCancelled)
        assertEquals(0, admittedDuringCancellation.get())
        assertNotNull(registry.claim(this, "pc") { })
        registry.cancelAll()
    }

    private class FlagCloseable : Closeable { var closed = false; override fun close() { closed = true } }
    private class ThrowingCloseable : Closeable { override fun close() { throw IllegalStateException("close") } }
}
