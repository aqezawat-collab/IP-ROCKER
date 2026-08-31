package com.qezawat.iprocker.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.doublePreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * Everything the user can tune about a scan.
 *
 * Defaults are chosen for a phone on a metered mobile connection: a few hundred
 * addresses, a download sample large enough to be meaningful but small enough
 * not to burn data, and the stability check on, because that
 * are the two things that separate a usable address from one that merely pings.
 */
data class ScanSettings(
    val count: Int = 500,
    val concurrency: Int = 100,
    val port: Int = 443,
    /**
     * Comma-separated extra ports probed alongside [port]. Empty means probe
     * only [port]. Every added port multiplies the number of probes.
     */
    val ports: String = "",
    val mode: String = "http",
    val tries: Int = 3,
    val timeoutMs: Int = 6000,
    val holdMs: Int = 3000,
    val downloadBytes: Long = 1024L * 1024,
    val uploadBytes: Long = 128L * 1024,
    /** Reject addresses slower than this many KB/s. Zero disables the filter. */
    val minSpeedKBps: Double = 0.0,

    val stabilityCheck: Boolean = true,
    val speedTest: Boolean = true,
    val uploadTest: Boolean = false,
    val longTest: Boolean = false,
    val longTestMs: Int = 15000,
    val strict: Boolean = false,
    val configLink: String = "",
    val sni: String = "",
    val host: String = "",
    val wsPath: String = "",
    val requireWebSocket: Boolean = false,

    val customRanges: String = "",
    val onlyCustomRanges: Boolean = false,

    /**
     * How many of the best candidates to keep for the report and export, mirroring
     * the TUI's "Phase 2 picks". The scan still probes [count] addresses; this
     * only caps what is surfaced. 0 means keep everything.
     */
    val topN: Int = 0,

    /**
     * What the export / copy buttons produce. "working" = only addresses that
     * passed every check (the Phase 2 output, saved as working_ips.txt); "phase1"
     * = every address that answered.
     */
    val exportMode: String = "working",

    /**
     * How custom ranges / IP text is split. "lines" accepts a file pasted
     * line-by-line (one CIDR or IP per line), which is what exported lists look
     * like; "comma" keeps the single-line comma form.
     */
    val importMode: String = "lines",
) {
    companion object {
        /** Ports Cloudflare terminates TLS on for a proxied hostname. */
        val COMMON_PORTS = listOf(443, 2053, 2083, 2087, 2096, 8443)

        /**
         * Address-count presets. The upper values exist because a sweep of a
         * space this large is how rare clean blocks get found at all; the app
         * warns rather than forbids, since the cost is time and data.
         */
        val PRESET_COUNTS = listOf(500, 2_500, 5_000, 10_000, 20_000)

        /** Parallelism presets, labelled by what they suit. */
        val PRESET_CONCURRENCY = listOf(50, 100, 200, 500)

        /**
         * Download-sample presets in bytes. Off is the download toggle's job.
         *
         * The top of this range is deliberately large: a 256 KB sample cannot
         * tell a 1 MB/s middlebox from a 5 MB/s edge, and separating those two
         * is the entire point of the throughput test. The caption warns about
         * the data cost instead of the range forbidding it.
         */
        val PRESET_DOWNLOAD_BYTES = listOf(
            128L * 1024, 256L * 1024, 512L * 1024,
            1024L * 1024, 2048L * 1024, 5120L * 1024,
            10240L * 1024, 20480L * 1024,
        )

        /**
         * Minimum-speed presets in KB/s; 0 means no filter. Reaches 5 MB/s
         * because that is what a genuinely usable edge measured on a real
         * censored mobile link, so the floor has to be expressible.
         */
        val PRESET_MIN_SPEED = listOf(0.0, 100.0, 250.0, 500.0, 1000.0, 2000.0, 5000.0)

        /** Upload-sample presets in bytes. */
        val PRESET_UPLOAD_BYTES = listOf(128L * 1024, 512L * 1024, 1024L * 1024, 2048L * 1024)

        /** Phase 2 pick presets; "all" keeps every candidate. */
        val PRESET_TOPN = listOf(0, 10, 25, 50, 100)

        /** How the export splits into Phase 1 (all answers) vs Phase 2 (working). */
        val EXPORT_MODES = listOf("working", "phase1")

        /** Custom-range import styles. */
        val IMPORT_MODES = listOf("lines", "comma")
    }

    /**
     * The ports this scan will probe. [ports] is the source of truth when set;
     * an empty list means the single [port], which keeps older saved settings
     * and config-link scans working unchanged.
     */
    fun selectedPorts(): List<Int> {
        val parsed = ports.split(',')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }
            .distinct()
        return if (parsed.isEmpty()) listOf(port) else parsed
    }

    /**
     * Adds or removes a port. Deselecting the last remaining port is ignored,
     * since a scan with no port cannot run; [port] tracks the first selection so
     * the single-port path stays consistent.
     */
    fun togglePort(p: Int): ScanSettings {
        val current = selectedPorts().toMutableList()
        if (p in current) {
            if (current.size == 1) return this
            current.remove(p)
        } else {
            current.add(p)
        }
        val ordered = COMMON_PORTS.filter { it in current } +
            current.filterNot { it in COMMON_PORTS }
        return copy(
            port = ordered.first(),
            ports = if (ordered.size == 1) "" else ordered.joinToString(","),
        )
    }
}

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "iprocker_settings")

/**
 * Persists scan settings so a repeat scan needs no retyping. The config link is
 * stored because re-pasting it on every run is the main friction point, and it
 * never leaves the device.
 */
class SettingsRepository(private val context: Context) {

    val settings: Flow<ScanSettings> = context.dataStore.data.map { p ->
        val d = ScanSettings()
        ScanSettings(
            count = p[Keys.COUNT] ?: d.count,
            concurrency = p[Keys.CONCURRENCY] ?: d.concurrency,
            port = p[Keys.PORT] ?: d.port,
            ports = p[Keys.PORTS] ?: d.ports,
            mode = p[Keys.MODE] ?: d.mode,
            tries = p[Keys.TRIES] ?: d.tries,
            timeoutMs = p[Keys.TIMEOUT] ?: d.timeoutMs,
            holdMs = p[Keys.HOLD] ?: d.holdMs,
            downloadBytes = p[Keys.DOWNLOAD] ?: d.downloadBytes,
            uploadBytes = p[Keys.UPLOAD] ?: d.uploadBytes,
            minSpeedKBps = p[Keys.MIN_SPEED] ?: d.minSpeedKBps,
            stabilityCheck = p[Keys.STABILITY] ?: d.stabilityCheck,
            speedTest = p[Keys.SPEED] ?: d.speedTest,
            uploadTest = p[Keys.UPLOAD_TEST] ?: d.uploadTest,
            longTest = p[Keys.LONG_TEST] ?: d.longTest,
            longTestMs = p[Keys.LONG_TEST_MS] ?: d.longTestMs,
            strict = p[Keys.STRICT] ?: d.strict,
            configLink = p[Keys.CONFIG_LINK] ?: d.configLink,
            sni = p[Keys.SNI] ?: d.sni,
            host = p[Keys.HOST] ?: d.host,
            wsPath = p[Keys.WS_PATH] ?: d.wsPath,
            requireWebSocket = p[Keys.REQUIRE_WS] ?: d.requireWebSocket,
            customRanges = p[Keys.CUSTOM_RANGES] ?: d.customRanges,
            onlyCustomRanges = p[Keys.ONLY_CUSTOM] ?: d.onlyCustomRanges,
            topN = p[Keys.TOP_N] ?: d.topN,
            exportMode = p[Keys.EXPORT_MODE] ?: d.exportMode,
            importMode = p[Keys.IMPORT_MODE] ?: d.importMode,
        )
    }

    suspend fun save(s: ScanSettings) {
        context.dataStore.edit { p ->
            p[Keys.COUNT] = s.count
            p[Keys.CONCURRENCY] = s.concurrency
            p[Keys.PORT] = s.port
            p[Keys.PORTS] = s.ports
            p[Keys.MODE] = s.mode
            p[Keys.TRIES] = s.tries
            p[Keys.TIMEOUT] = s.timeoutMs
            p[Keys.HOLD] = s.holdMs
            p[Keys.DOWNLOAD] = s.downloadBytes
            p[Keys.UPLOAD] = s.uploadBytes
            p[Keys.MIN_SPEED] = s.minSpeedKBps
            p[Keys.STABILITY] = s.stabilityCheck
            p[Keys.SPEED] = s.speedTest
            p[Keys.UPLOAD_TEST] = s.uploadTest
            p[Keys.LONG_TEST] = s.longTest
            p[Keys.LONG_TEST_MS] = s.longTestMs
            p[Keys.STRICT] = s.strict
            p[Keys.CONFIG_LINK] = s.configLink
            p[Keys.SNI] = s.sni
            p[Keys.HOST] = s.host
            p[Keys.WS_PATH] = s.wsPath
            p[Keys.REQUIRE_WS] = s.requireWebSocket
            p[Keys.CUSTOM_RANGES] = s.customRanges
            p[Keys.ONLY_CUSTOM] = s.onlyCustomRanges
            p[Keys.TOP_N] = s.topN
            p[Keys.EXPORT_MODE] = s.exportMode
            p[Keys.IMPORT_MODE] = s.importMode
        }
    }

    private object Keys {
        val COUNT = intPreferencesKey("count")
        val CONCURRENCY = intPreferencesKey("concurrency")
        val PORT = intPreferencesKey("port")
        val PORTS = stringPreferencesKey("ports")
        val MODE = stringPreferencesKey("mode")
        val TRIES = intPreferencesKey("tries")
        val TIMEOUT = intPreferencesKey("timeout_ms")
        val HOLD = intPreferencesKey("hold_ms")
        val DOWNLOAD = longPreferencesKey("download_bytes")
        val UPLOAD = longPreferencesKey("upload_bytes")
        val MIN_SPEED = doublePreferencesKey("min_speed_kbps")
        val STABILITY = booleanPreferencesKey("stability")
        val SPEED = booleanPreferencesKey("speed")
        val UPLOAD_TEST = booleanPreferencesKey("upload_test")
        val LONG_TEST = booleanPreferencesKey("long_test")
        val LONG_TEST_MS = intPreferencesKey("long_test_ms")
        val STRICT = booleanPreferencesKey("strict")
        val CONFIG_LINK = stringPreferencesKey("config_link")
        val SNI = stringPreferencesKey("sni")
        val HOST = stringPreferencesKey("host")
        val WS_PATH = stringPreferencesKey("ws_path")
        val REQUIRE_WS = booleanPreferencesKey("require_ws")
        val CUSTOM_RANGES = stringPreferencesKey("custom_ranges")
        val ONLY_CUSTOM = booleanPreferencesKey("only_custom")
        val TOP_N = intPreferencesKey("top_n")
        val EXPORT_MODE = stringPreferencesKey("export_mode")
        val IMPORT_MODE = stringPreferencesKey("import_mode")
    }
}
