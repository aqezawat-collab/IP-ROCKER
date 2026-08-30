package com.qezawat.iprocker.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.qezawat.iprocker.data.Candidate
import com.qezawat.iprocker.ui.theme.RockerAccent
import com.qezawat.iprocker.ui.theme.RockerOutline
import com.qezawat.iprocker.ui.theme.RockerSurface
import com.qezawat.iprocker.ui.theme.RockerSurfaceHigh
import com.qezawat.iprocker.ui.theme.TextSecondary
import com.qezawat.iprocker.ui.theme.VerdictClean
import com.qezawat.iprocker.ui.theme.VerdictDirty

/**
 * One result row.
 *
 * The layout leads with the address and its verdict, because those are the two
 * things the user acts on. Measurements sit underneath as compact metric chips,
 * and a rejected address shows the reason instead of pretending to be usable.
 */
@Composable
fun ResultCard(
    candidate: Candidate,
    rank: Int,
    onDetails: (Candidate) -> Unit,
    onCopy: (Candidate) -> Unit,
    modifier: Modifier = Modifier,
) {
    val accent = if (candidate.healthy) VerdictClean else VerdictDirty

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(RockerSurface)
            .border(1.dp, if (candidate.healthy) accent.copy(alpha = 0.35f) else RockerOutline, RoundedCornerShape(16.dp))
            .clickable { onDetails(candidate) }
            .padding(14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RankBadge(rank, candidate.healthy)
            Spacer(Modifier.width(10.dp))

            Column(Modifier.weight(1f)) {
                Text(
                    text = candidate.endpoint,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    text = candidate.headline,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (candidate.healthy) TextSecondary else VerdictDirty,
                    maxLines = 2,
                )
            }

            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = "%.0f".format(candidate.score),
                    style = MaterialTheme.typography.titleMedium,
                    color = accent,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = "score",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                )
            }
        }

        Spacer(Modifier.height(10.dp))

        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            MetricChip("${candidate.avgLatencyMs.toInt()}ms", "latency")
            // Keep both throughput metrics visible even when a test was not
            // run or its endpoint was unavailable. Hiding the chip made it look
            // like the scanner had no download/upload support at all, while the
            // detail sheet already reports the honest fallback value.
            MetricChip(displaySpeed(candidate.downloadKbps), "down")
            MetricChip(displaySpeed(candidate.uploadKbps), "up")
            if (candidate.colo.isNotBlank()) {
                MetricChip(candidate.colo, "colo")
            }
        }

        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (candidate.heldOpen) TagPill("STABLE")
            if (candidate.webSocketOk) {
                Spacer(Modifier.width(4.dp))
                TagPill("WS")
            }
            Spacer(Modifier.weight(1f))

            IconButton(
                onClick = { onCopy(candidate) },
                modifier = Modifier
                    .size(34.dp)
                    .semantics { contentDescription = "Copy ${candidate.endpoint}" },
            ) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = null,
                    tint = RockerAccent,
                    modifier = Modifier.size(17.dp),
                )
            }
            IconButton(
                onClick = { onDetails(candidate) },
                modifier = Modifier
                    .size(34.dp)
                    .semantics { contentDescription = "Details for ${candidate.ip}" },
            ) {
                Icon(
                    Icons.Default.Info,
                    contentDescription = null,
                    tint = TextSecondary,
                    modifier = Modifier.size(17.dp),
                )
            }
        }
    }
}

@Composable
private fun RankBadge(rank: Int, healthy: Boolean) {
    val color = if (healthy) RockerAccent else TextSecondary
    Box(
        Modifier
            .size(30.dp)
            .clip(RoundedCornerShape(9.dp))
            .background(color.copy(alpha = 0.14f)),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = "$rank",
            style = MaterialTheme.typography.labelMedium,
            color = color,
            fontWeight = FontWeight.Bold,
        )
    }
}

@Composable
private fun MetricChip(value: String, label: String) {
    Column(
        Modifier
            .clip(RoundedCornerShape(9.dp))
            .background(RockerSurfaceHigh)
            .padding(horizontal = 8.dp, vertical = 5.dp),
    ) {
        Text(
            text = value,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = TextSecondary,
        )
    }
}

@Composable
private fun TagPill(text: String, color: Color = RockerAccent) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = color,
        fontWeight = FontWeight.Bold,
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.14f))
            .padding(horizontal = 8.dp, vertical = 3.dp),
    )
}

/** Renders throughput in the unit that keeps the number readable. */
fun formatSpeed(kbps: Double): String = when {
    kbps >= 1024 -> "%.1f MB/s".format(kbps / 1024)
    kbps >= 1 -> "%.0f KB/s".format(kbps)
    else -> "<1 KB/s"
}

/**
 * Keeps a metric present when it was not measured, instead of removing the
 * entire download/upload indicator from the result card.
 */
fun displaySpeed(kbps: Double): String = if (kbps > 0) formatSpeed(kbps) else "—"
