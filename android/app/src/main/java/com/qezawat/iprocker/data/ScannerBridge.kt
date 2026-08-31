package com.qezawat.iprocker.data

import android.util.Log
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import mobile.Mobile
import mobile.ProgressListener
import mobile.ScanRequest as GoScanRequest
import mobile.Scanner as GoScanner

/**
 * Bridges the Go scanner core to Kotlin flows.
 *
 * gomobile callbacks arrive on Go-owned threads, so every value is published
 * through a flow rather than touched directly by the UI. Results cross the
 * boundary as JSON because gomobile cannot bind slices of structs.
 */
class ScannerBridge {

    data class Progress(
        val phase: String = "idle",
        val tested: Int = 0,
        val total: Int = 0,
        val hits: Int = 0,
        val inFlight: Int = 0,
    )

    sealed interface Event {
        data class Hit(val candidate: Candidate) : Event
        data class Finished(val report: ScanReport) : Event
        data class Failed(val message: String) : Event
        data class Log(val message: String) : Event
    }

    private val goScanner: GoScanner = Mobile.newScanner()

    private val _progress = MutableStateFlow(Progress())
    val progress: StateFlow<Progress> = _progress.asStateFlow()

    private val _events = MutableSharedFlow<Event>(
        replay = 0,
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val events: SharedFlow<Event> = _events.asSharedFlow()

    val isRunning: Boolean get() = goScanner.isRunning

    /**
     * Builds a Go scan request from UI settings. Returns the request plus a
     * description of what a pasted config link contributed, or throws with a
     * message safe to show the user.
     */
    fun buildRequest(settings: ScanSettings): Pair<GoScanRequest, String?> {
        val req = Mobile.newScanRequest()
        req.setCount(settings.count)
        req.setConcurrency(settings.concurrency)
        req.setPort(settings.port)
        // Empty means the single port above; a list multiplies the probe count.
        req.setPorts(settings.ports)
        req.setMode(settings.mode)
        req.setTries(settings.tries)
        req.setTimeoutMs(settings.timeoutMs)
        req.setHoldMs(if (settings.stabilityCheck) settings.holdMs else 0)
        req.setLongTest(settings.longTest)
        req.setLongTestMs(settings.longTestMs)
        req.setDownloadBytes(if (settings.speedTest) settings.downloadBytes else 0L)
        req.setUploadBytes(if (settings.uploadTest) settings.uploadBytes else 0L)
        // A speed floor is only meaningful when a download sample is taken.
        req.setMinSpeedKBps(if (settings.speedTest) settings.minSpeedKBps else 0.0)
        req.setStrict(settings.strict)
        req.setTopN(settings.topN)
        req.setExportMode(settings.exportMode)
        req.setImportMode(settings.importMode)
        req.setOnlyExtra(settings.onlyCustomRanges)
        req.setExtraCIDRs(settings.customRanges)

        var applied: String? = null
        val link = settings.configLink.trim()
        if (link.isNotEmpty()) {
            // Deriving SNI, Host, path and port from the user's own config means
            // the scan measures the exact front their traffic will use.
            applied = req.applyConfigURL(link)
        } else {
            if (settings.sni.isNotBlank()) req.setSNI(settings.sni.trim())
            if (settings.host.isNotBlank()) req.setHost(settings.host.trim())
            if (settings.wsPath.isNotBlank()) {
                req.setWebSocketPath(settings.wsPath.trim())
                req.setRequireWebSocket(settings.requireWebSocket)
            }
        }
        return req to applied
    }

    /** Starts a scan. Throws with a user-facing message if it cannot start. */
    fun start(request: GoScanRequest) {
        _progress.value = Progress(phase = "starting")
        goScanner.start(request, listener)
    }

    fun stop() {
        goScanner.stop()
    }

    /** The measured cleanliness profile of the built-in ranges. */
    fun blockProfile(): List<BlockInfo> =
        runCatching { IPRockerJson.decodeFromString<List<BlockInfo>>(Mobile.blockProfileJSON()) }
            .getOrElse { emptyList() }

    private val listener = object : ProgressListener {
        // gomobile binds Go int32 to a plain Java int.
        override fun onProgress(phase: String, tested: Int, total: Int, hits: Int, inFlight: Int) {
            _progress.value = Progress(
                phase = phase,
                tested = tested,
                total = total,
                hits = hits,
                inFlight = inFlight,
            )
        }

        override fun onHit(candidateJSON: String) {
            val candidate = runCatching {
                IPRockerJson.decodeFromString<Candidate>(candidateJSON)
            }.getOrElse {
                Log.w(TAG, "could not decode hit payload", it)
                return
            }
            _events.tryEmit(Event.Hit(candidate))
        }

        override fun onFinished(reportJSON: String, err: String) {
            if (err.isNotEmpty()) {
                _events.tryEmit(Event.Failed(err))
                return
            }
            val report = runCatching {
                IPRockerJson.decodeFromString<ScanReport>(reportJSON)
            }.getOrElse {
                _events.tryEmit(Event.Failed("Scan finished but the report could not be read: ${it.message}"))
                return
            }
            _events.tryEmit(Event.Finished(report))
        }

        override fun onLog(message: String) {
            _events.tryEmit(Event.Log(message))
        }
    }

    private companion object {
        const val TAG = "ScannerBridge"
    }
}

@kotlinx.serialization.Serializable
data class BlockInfo(
    val cidr: String = "",
    val weight: Double = 1.0,
    val note: String = "",
)
