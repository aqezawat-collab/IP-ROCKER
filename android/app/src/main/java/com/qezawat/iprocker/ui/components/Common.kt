package com.qezawat.iprocker.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.qezawat.iprocker.ui.theme.RockerAccent
import com.qezawat.iprocker.ui.theme.RockerOutline
import com.qezawat.iprocker.ui.theme.RockerSurface
import com.qezawat.iprocker.ui.theme.RockerSurfaceHigh
import com.qezawat.iprocker.ui.theme.TextSecondary
import com.qezawat.iprocker.ui.theme.VerdictClean
import com.qezawat.iprocker.ui.theme.VerdictDirty

/**
 * A card surface used for every grouped block of content.
 */
@Composable
fun RockerCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(RockerSurface)
            .border(1.dp, RockerOutline, RoundedCornerShape(18.dp))
            .padding(16.dp),
        content = content,
    )
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = RockerAccent,
        fontWeight = FontWeight.Bold,
        modifier = modifier,
    )
}

/**
 * A wrapping row of preset chips. Wraps rather than clipping, because the useful
 * presets outgrew a single line once large sweeps were allowed.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun <T> ChoiceChips(
    options: List<T>,
    selected: (T) -> Boolean,
    label: (T) -> String,
    onSelect: (T) -> Unit,
    modifier: Modifier = Modifier,
) {
    FlowRow(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        options.forEach { option ->
            val on = selected(option)
            AssistChip(
                onClick = { onSelect(option) },
                label = { Text(label(option)) },
                colors = AssistChipDefaults.assistChipColors(
                    containerColor = if (on) RockerAccent.copy(alpha = 0.18f) else RockerSurfaceHigh,
                    labelColor = if (on) RockerAccent else TextSecondary,
                ),
            )
        }
    }
}

/** A small key/value row used throughout the details sheet. */
@Composable
fun DetailRow(
    label: String,
    value: String,
    valueColor: Color = MaterialTheme.colorScheme.onSurface,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
        )
        Spacer(Modifier.width(12.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.labelMedium,
            color = valueColor,
        )
    }
}

/** A pass/fail check with an explicit word, never colour alone. */
@Composable
fun FlagChip(label: String, passed: Boolean, modifier: Modifier = Modifier) {
    val tint = if (passed) VerdictClean else VerdictDirty
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(RockerSurfaceHigh)
            .padding(horizontal = 10.dp, vertical = 8.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
        )
        Spacer(Modifier.height(2.dp))
        Text(
            text = if (passed) "YES" else "NO",
            style = MaterialTheme.typography.labelMedium,
            color = tint,
            fontWeight = FontWeight.Bold,
        )
    }
}

/**
 * A progress bar that animates indeterminately while a phase has no known
 * total, so the user can tell the app is working rather than stalled.
 */
@Composable
fun ScanProgressBar(
    fraction: Float,
    indeterminate: Boolean,
    modifier: Modifier = Modifier,
) {
    if (indeterminate) {
        val transition = rememberInfiniteTransition(label = "scanPulse")
        val shift by transition.animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(1200),
                repeatMode = RepeatMode.Restart,
            ),
            label = "shift",
        )
        Box(
            modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(50))
                .background(RockerSurfaceHigh),
        ) {
            Box(
                Modifier
                    .fillMaxWidth(0.35f)
                    .height(6.dp)
                    .alpha(0.9f)
                    .background(
                        Brush.horizontalGradient(
                            listOf(Color.Transparent, RockerAccent, Color.Transparent),
                        ),
                    )
                    .padding(start = (shift * 200).dp),
            )
        }
    } else {
        LinearProgressIndicator(
            progress = { fraction },
            modifier = modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(50)),
            color = RockerAccent,
            trackColor = RockerSurfaceHigh,
        )
    }
}
