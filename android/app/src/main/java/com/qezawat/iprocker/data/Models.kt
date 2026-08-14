package com.qezawat.iprocker.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The JSON contract with the Go core. Field names mirror the struct tags in
 * internal/score; changing one side requires changing the other.
 */
val IPRockerJson: Json = Json {
    ignoreUnknownKeys = true
    isLenient = true
    explicitNulls = false
}

@Serializable
data class Candidate(
    val ip: String = "",
    val port: Int = 443,
    @SerialName("avg_latency_ms") val avgLatencyMs: Double = 0.0,
    @SerialName("min_latency_ms") val minLatencyMs: Double = 0.0,
    @SerialName("jitter_ms") val jitterMs: Double = 0.0,
    @SerialName("loss_percent") val lossPercent: Double = 0.0,
    @SerialName("download_kbps") val downloadKbps: Double = 0.0,
    @SerialName("upload_kbps") val uploadKbps: Double = 0.0,
    val colo: String = "",
    @SerialName("held_open") val heldOpen: Boolean = false,
    @SerialName("websocket_ok") val webSocketOk: Boolean = false,
    @SerialName("tls_ok") val tlsOk: Boolean = false,
    val score: Double = 0.0,
    val healthy: Boolean = false,
    val notes: List<String> = emptyList(),
) {
    val endpoint: String get() = "$ip:$port"

    val headline: String
        get() = when {
            !healthy && notes.isNotEmpty() -> notes.first()
            else -> "measured edge"
        }
}

@Serializable
data class ScanReport(
    val tested: Long = 0,
    val hits: Long = 0,
    @SerialName("duration_ms") val durationMs: Long = 0,
    val candidates: List<Candidate> = emptyList(),
) {
    val clean: List<Candidate> get() = candidates.filter { it.healthy }
    val cleanCount: Int get() = clean.size
}

@Serializable
data class ConfigLinkInfo(
    val protocol: String = "",
    val sni: String = "",
    val host: String = "",
    val path: String = "",
    val port: Int = 0,
    val transport: String = "",
    val security: String = "",
    val address: String = "",
)
