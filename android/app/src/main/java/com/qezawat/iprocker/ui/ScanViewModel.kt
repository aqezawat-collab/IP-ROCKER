package com.qezawat.iprocker.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.qezawat.iprocker.data.BlockInfo
import com.qezawat.iprocker.data.Candidate
import com.qezawat.iprocker.data.ScanReport
import com.qezawat.iprocker.data.ScanSettings
import com.qezawat.iprocker.data.ScannerBridge
import com.qezawat.iprocker.data.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Which result group the list is showing. */
enum class ResultFilter { USABLE, ALL, FLAGGED }

data class UiState(
    val settings: ScanSettings = ScanSettings(),
    val scanning: Boolean = false,
    val phase: String = "idle",
    val tested: Int = 0,
    val total: Int = 0,
    val hits: Int = 0,
    val inFlight: Int = 0,

    /** Candidates streaming in during the probe phase, before rating. */
    val liveHits: List<Candidate> = emptyList(),
    val report: ScanReport? = null,
    val filter: ResultFilter = ResultFilter.USABLE,

    /** A message shown once, then cleared. */
    val message: String? = null,
    /** Set when a config link was parsed, describing what it changed. */
    val configApplied: String? = null,

    val blockProfile: List<BlockInfo> = emptyList(),

    /** The candidate whose detail sheet is open, or null when none is shown. */
    val selected: Candidate? = null,
) {
    val visibleResults: List<Candidate>
        get() {
            val r = report
            // When the report has no candidates (e.g. scan ended early
            // out), fall back to live hits so the user never sees an empty list
            // after a scan that clearly found addresses.
            if (r == null || r.candidates.isEmpty()) {
                return when (filter) {
                    ResultFilter.USABLE -> liveHits.filter { it.healthy }
                    ResultFilter.FLAGGED -> liveHits.filter { !it.healthy }
                    ResultFilter.ALL -> liveHits
                }.sortedByDescending { it.score }
            }
            return when (filter) {
                ResultFilter.USABLE -> r.candidates.filter { it.healthy }
                ResultFilter.FLAGGED -> r.candidates.filter { !it.healthy }
                ResultFilter.ALL -> r.candidates
            }
        }

    val progressFraction: Float
        get() = when {
            total > 0 -> (tested.toFloat() / total).coerceIn(0f, 1f)
            else -> 0f
        }
}

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val bridge = ScannerBridge()
    private val settingsRepo = SettingsRepository(app)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            settingsRepo.settings.collect { saved ->
                _state.update { it.copy(settings = saved) }
            }
        }
        viewModelScope.launch {
            bridge.progress.collect { p ->
                _state.update {
                    it.copy(
                        phase = p.phase,
                        tested = p.tested,
                        total = p.total,
                        hits = p.hits,
                        inFlight = p.inFlight,
                    )
                }
            }
        }
        viewModelScope.launch {
            bridge.events.collect { event ->
                when (event) {
                    is ScannerBridge.Event.Hit -> _state.update {
                        // Cap the live list: during a large scan the report at
                        // the end is authoritative, and an unbounded list would
                        // make recomposition expensive.
                        val next = (it.liveHits + event.candidate).takeLast(200)
                        it.copy(liveHits = next)
                    }

                    is ScannerBridge.Event.Finished -> _state.update {
                        val note = when {
                            event.report.cleanCount == 0 && event.report.hits > 0 ->
                                "${event.report.hits} addresses answered but none passed every check. " +
                                    "Try turning off Strict, or scan more addresses."
                            event.report.hits == 0L ->
                                "No address answered. Your network may be blocking the whole range, " +
                                    "or the port and SNI do not match your config."
                            else -> null
                        }
                        it.copy(
                            scanning = false,
                            report = event.report,
                            phase = "done",
                            message = note,
                        )
                    }

                    is ScannerBridge.Event.Failed -> _state.update {
                        it.copy(scanning = false, phase = "failed", message = event.message)
                    }

                    is ScannerBridge.Event.Log -> _state.update {
                        it.copy(message = event.message)
                    }
                }
            }
        }
        viewModelScope.launch {
            val profile = withContext(Dispatchers.IO) { bridge.blockProfile() }
            _state.update { it.copy(blockProfile = profile) }
        }
    }

    fun updateSettings(transform: (ScanSettings) -> ScanSettings) {
        val next = transform(_state.value.settings)
        _state.update { it.copy(settings = next) }
        viewModelScope.launch { settingsRepo.save(next) }
    }

    /** Replaces the custom ranges text (from a pasted file) and switches the
     * import mode to line-by-line so each line is treated as one CIDR or IP. */
    fun setCustomRanges(text: String) {
        updateSettings { it.copy(customRanges = text, importMode = "lines") }
    }

    fun startScan() {
        if (_state.value.scanning) return

        _state.update {
            it.copy(
                scanning = true,
                phase = "starting",
                tested = 0,
                hits = 0,
                total = it.settings.count,
                liveHits = emptyList(),
                report = null,
                message = null,
                configApplied = null,
            )
        }

        viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val (request, applied) = bridge.buildRequest(_state.value.settings)
                    bridge.start(request)
                    applied
                }
            }
            result.onSuccess { applied ->
                if (applied != null) {
                    _state.update { it.copy(configApplied = "Using your config: $applied") }
                }
            }.onFailure { e ->
                // Surface the real reason, including the explanation for why a
                // REALITY link cannot be scanned behind Cloudflare.
                _state.update {
                    it.copy(
                        scanning = false,
                        phase = "failed",
                        message = e.message ?: "Could not start the scan",
                    )
                }
            }
        }
    }

    fun stopScan() {
        bridge.stop()
        _state.update { it.copy(phase = "stopping") }
    }

    fun setFilter(f: ResultFilter) = _state.update { it.copy(filter = f) }

    fun consumeMessage() = _state.update { it.copy(message = null) }
    fun updateMessage(text: String) = _state.update { it.copy(message = text) }

    fun consumeConfigApplied() = _state.update { it.copy(configApplied = null) }

    /** Opens the detail sheet for a candidate (the result row's tap target). */
    fun showDetails(c: Candidate) = _state.update { it.copy(selected = c) }

    /** Closes the detail sheet. */
    fun dismissDetails() = _state.update { it.copy(selected = null) }

    /**
     * The endpoints as text for copying or saving. mode selects the content:
     * "working" keeps only addresses that passed every check (Phase 2), "phase1"
     * keeps every address that answered. The export respects the Top N setting by
     * taking the highest-scoring candidates first.
     */
    fun exportText(mode: String = _state.value.settings.exportMode): String {
        val report = _state.value.report
        val live = _state.value.liveHits

        // Prefer the authoritative report, but fall back to live hits when the
        // report is absent OR its candidate list is empty (e.g. scan
        // phase timed out after probing found hundreds of addresses).
        val source: List<Candidate> = when {
            report != null && report.candidates.isNotEmpty() ->
                if (mode == "working") report.clean else report.candidates
            live.isNotEmpty() ->
                live.filter { if (mode == "working") it.healthy else true }
                    .sortedByDescending { it.score }
            else -> return ""
        }
        if (source.isEmpty()) return ""
        return source.joinToString("\n") { it.endpoint }
    }

    /** Phase 2 output: only the working addresses, saved as working_ips.txt. */
    fun exportWorkingText(): String = exportText("working")

    override fun onCleared() {
        bridge.stop()
        super.onCleared()
    }
}
