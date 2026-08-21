package com.qezawat.iprocker.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Share
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.qezawat.iprocker.data.Candidate
import com.qezawat.iprocker.ui.components.ResultCard
import com.qezawat.iprocker.ui.components.RockerCard
import com.qezawat.iprocker.ui.components.ScanProgressBar
import com.qezawat.iprocker.ui.components.SectionLabel
import com.qezawat.iprocker.ui.components.DetailRow
import com.qezawat.iprocker.ui.components.FlagChip
import com.qezawat.iprocker.ui.components.formatSpeed
import com.qezawat.iprocker.ui.theme.RockerAccent
import com.qezawat.iprocker.ui.theme.RockerBackground
import com.qezawat.iprocker.ui.theme.RockerSurfaceHigh
import com.qezawat.iprocker.ui.theme.TextSecondary
import com.qezawat.iprocker.ui.theme.VerdictCaution
import com.qezawat.iprocker.ui.theme.VerdictClean
import com.qezawat.iprocker.ui.theme.VerdictDirty

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(viewModel: ScanViewModel = viewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val snackbarHost = remember { SnackbarHostState() }

    var showSettings by remember { mutableStateOf(false) }

    // Picks a text file (ips.txt / cidr.txt) and loads its contents into the
    // custom ranges, switching import to line-by-line so every line is one
    // CIDR or IP. The file is read here and handed to the ViewModel as text.
    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent(),
        onResult = { uri: Uri? ->
            uri ?: return@rememberLauncherForActivityResult
            val text = context.contentResolver.openInputStream(uri)?.use { stream ->
                stream.bufferedReader().readText()
            } ?: return@rememberLauncherForActivityResult
            viewModel.setCustomRanges(text)
        },
    )

    // Lets the user pick where to save the Phase 2 working list, mirroring the
    // TUI's export step rather than silently dumping into Downloads.
    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain"),
        onResult = { uri: Uri? ->
            uri ?: return@rememberLauncherForActivityResult
            val text = viewModel.exportWorkingText()
            if (text.isEmpty()) return@rememberLauncherForActivityResult
            context.contentResolver.openOutputStream(uri)?.use { out ->
                out.write(text.toByteArray(Charsets.UTF_8))
            }
            viewModel.updateMessage("Exported working_ips.txt")
        },
    )

    // Messages are surfaced once and cleared, so a stale error never lingers.
    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHost.showSnackbar(it)
            viewModel.consumeMessage()
        }
    }
    LaunchedEffect(state.configApplied) {
        state.configApplied?.let {
            snackbarHost.showSnackbar(it)
            viewModel.consumeConfigApplied()
        }
    }

    Scaffold(
        containerColor = RockerBackground,
        snackbarHost = { SnackbarHost(snackbarHost) },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            "IP ROCKER",
                            style = MaterialTheme.typography.titleLarge,
                            color = RockerAccent,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            "clean Cloudflare edges, not just fast ones",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary,
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showSettings = true },
                        modifier = Modifier.semantics { contentDescription = "Scan settings" },
                    ) {
                        Icon(Icons.Default.Settings, contentDescription = null, tint = TextSecondary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = RockerBackground),
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                ControlCard(
                    state = state,
                    onStart = viewModel::startScan,
                    onStop = viewModel::stopScan,
                    onCopyPhase1 = {
                        val text = viewModel.exportText("phase1")
                        if (text.isEmpty()) return@ControlCard
                        copyToClipboard(context, text)
                    },
                    onCopyWorking = {
                        val text = viewModel.exportWorkingText()
                        if (text.isEmpty()) return@ControlCard
                        copyToClipboard(context, text)
                    },
                    onSaveWorking = {
                        // Open a file picker so the user chooses where to save,
                        // like the TUI export step, instead of a fixed Downloads path.
                        if (viewModel.exportWorkingText().isEmpty()) return@ControlCard
                        exportLauncher.launch("working_ips.txt")
                    },
                    onShare = {
                        val text = viewModel.exportText("phase1")
                        if (text.isEmpty()) return@ControlCard
                        shareText(context, text)
                    },
                )
            }

            // state.report is a delegated property, so it cannot be smart-cast to
            // a non-null ScanReport after a null check. Snapshot it into a local
            // val (stable) before using it inside the conditional.
            val report = state.report
            if (report != null) {
                item {
                    SectionLabel(
                        "Phase 2 · ${report.cleanCount} usable of ${report.candidates.size}",
                    )
                }
            }

            if (state.report != null || state.liveHits.isNotEmpty()) {
                item {
                    FilterRow(
                        current = state.filter,
                        usableCount = state.report?.cleanCount ?: state.liveHits.count { it.healthy },
                        // answeredCount = addresses that responded (candidates list)
                        answeredCount = state.report?.candidates?.size ?: state.liveHits.size,
                        // testedCount = every address probed, including no-response ones
                        testedCount = state.report?.tested?.toInt() ?: state.tested,
                        onSelect = viewModel::setFilter,
                    )
                }
            }

            val results = state.visibleResults
            itemsIndexed(
                items = results,
                key = { _, candidate -> candidate.endpoint },
            ) { index, candidate ->
                ResultCard(
                    candidate = candidate,
                    rank = index + 1,
                    onDetails = viewModel::showDetails,
                    onCopy = { copyToClipboard(context, it.endpoint) },
                )
            }

            if (results.isEmpty() && !state.scanning) {
                item { EmptyState(state.report == null) }
            }

            item { Spacer(Modifier.height(24.dp)) }
        }
    }

    if (showSettings) {
        SettingsSheet(
            settings = state.settings,
            onChange = viewModel::updateSettings,
            onImportFile = { importLauncher.launch("*/*") },
            onDismiss = { showSettings = false },
        )
    }

    state.selected?.let { selected ->
        DetailSheet(candidate = selected, onDismiss = viewModel::dismissDetails)
    }
}

@Composable
private fun ControlCard(
    state: UiState,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onCopyPhase1: () -> Unit,
    onCopyWorking: () -> Unit,
    onSaveWorking: () -> Unit,
    onShare: () -> Unit,
) {
    RockerCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                SectionLabel(if (state.scanning) state.phase else "ready")
                Spacer(Modifier.height(4.dp))
                // Snapshot the delegated property so the when branch can use it
                // without a smart-cast, which delegated properties forbid.
                val report = state.report
                Text(
                    text = when {
                        state.scanning -> "${state.tested} probed · ${state.hits} answered"
                        report != null ->
                            "${report.tested} probed · ${report.cleanCount} usable"
                        else -> "${state.settings.count} addresses queued"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            // Phase 1 copies every address that answered; Phase 2 copies only the
            // working ones and also offers to save them as working_ips.txt.
            // Show copy button whenever there are results — from the final report
            // or from live hits that streamed in during probing.  A scan that
            // timed out during probing still has usable Phase 1 data.
            if (state.report?.candidates?.isNotEmpty() == true || state.liveHits.isNotEmpty()) {
                IconButton(
                    onClick = onCopyPhase1,
                    modifier = Modifier.semantics { contentDescription = "Copy all answered endpoints" },
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, tint = TextSecondary)
                }
            }
            if (state.report?.cleanCount?.let { it > 0 } == true ||
                (state.report != null && state.liveHits.any { it.healthy })) {
                IconButton(
                    onClick = onCopyWorking,
                    modifier = Modifier.semantics { contentDescription = "Copy working endpoints" },
                ) {
                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = RockerAccent)
                }
                IconButton(
                    onClick = onSaveWorking,
                    modifier = Modifier.semantics { contentDescription = "Save working_ips.txt" },
                ) {
                    Icon(Icons.Default.Save, contentDescription = null, tint = RockerAccent)
                }
            }
            // Share button — always visible when there are results, so the user
            // can send the list straight to Telegram, WhatsApp, etc.
            if (state.report?.candidates?.isNotEmpty() == true || state.liveHits.isNotEmpty()) {
                IconButton(
                    onClick = onShare,
                    modifier = Modifier.semantics { contentDescription = "Share results" },
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, tint = TextSecondary)
                }
            }
        }

        AnimatedVisibility(visible = state.scanning) {
            Column {
                Spacer(Modifier.height(12.dp))
                ScanProgressBar(
                    fraction = state.progressFraction,
                    // The probing phase has no per-address total, so an
                    // indeterminate bar is honest rather than a fake percentage.
                    indeterminate = state.total <= 0 || state.phase.startsWith("checking"),
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "${state.inFlight} in flight",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                )
            }
        }

        Spacer(Modifier.height(14.dp))

        Button(
            onClick = if (state.scanning) onStop else onStart,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (state.scanning) {
                    MaterialTheme.colorScheme.error
                } else {
                    RockerAccent
                },
            ),
        ) {
            Icon(
                imageVector = if (state.scanning) Icons.Default.Stop else Icons.Default.PlayArrow,
                contentDescription = null,
                modifier = Modifier.size(22.dp),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = if (state.scanning) "STOP" else "START SCAN",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
private fun FilterRow(
    current: ResultFilter,
    usableCount: Int,
    answeredCount: Int,
    testedCount: Int,
    onSelect: (ResultFilter) -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        // All  = every address that answered (candidates — the ones the Go core
        //        measured and returned; no-response addresses are never sent back
        //        because there is nothing to show for them).
        // Rejected = answered but failed at least one check (!healthy)
        // The testedCount badge on All is intentionally the full probed count so
        // the user knows how many were swept, even though the list only shows
        // the ones that answered.
        val flaggedCount = answeredCount - usableCount
        val options = listOf(
            ResultFilter.USABLE to "Usable ($usableCount)",
            ResultFilter.ALL to "All probed ($testedCount)",
            ResultFilter.FLAGGED to "Rejected ($flaggedCount)",
        )
        options.forEach { (filter, label) ->
            FilterChip(
                selected = current == filter,
                onClick = { onSelect(filter) },
                label = { Text(label, style = MaterialTheme.typography.bodySmall) },
                colors = FilterChipDefaults.filterChipColors(
                    containerColor = RockerSurfaceHigh,
                    selectedContainerColor = RockerAccent.copy(alpha = 0.18f),
                    labelColor = TextSecondary,
                    selectedLabelColor = RockerAccent,
                ),
            )
        }
    }
}

@Composable
private fun EmptyState(neverRun: Boolean) {
    RockerCard {
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = if (neverRun) "No scan yet" else "Nothing to show",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = if (neverRun) {
                        "Paste your config link in settings for results that match " +
                            "your own front, then start the scan."
                    } else {
                        "Try a larger address count, or switch off Strict mode in settings."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DetailSheet(
    candidate: Candidate,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = RockerBackground,
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 18.dp)
                .padding(bottom = 36.dp),
        ) {
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        text = candidate.endpoint,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.Bold,
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = if (candidate.healthy) "USABLE" else "REJECTED",
                        style = MaterialTheme.typography.labelSmall,
                        color = if (candidate.healthy) VerdictClean else VerdictDirty,
                        fontWeight = FontWeight.Bold,
                    )
                }
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondary)
                }
            }

            Spacer(Modifier.height(12.dp))

            RockerCard {
                SectionLabel("Measurements")
                Spacer(Modifier.height(8.dp))
                DetailRow("Score", "%.0f".format(candidate.score))
                DetailRow("Avg latency", "${candidate.avgLatencyMs.toInt()} ms")
                DetailRow("Min latency", "${candidate.minLatencyMs.toInt()} ms")
                DetailRow("Jitter", "${candidate.jitterMs.toInt()} ms")
                DetailRow("Loss", "${candidate.lossPercent.toInt()} %")
                if (candidate.downloadKbps > 0) {
                    DetailRow("Download", formatSpeed(candidate.downloadKbps))
                }
                if (candidate.uploadKbps > 0) {
                    DetailRow("Upload", formatSpeed(candidate.uploadKbps))
                }
                if (candidate.colo.isNotBlank()) {
                    DetailRow("Colo", candidate.colo)
                }
            }

            Spacer(Modifier.height(12.dp))

            RockerCard {
                SectionLabel("Checks")
                Spacer(Modifier.height(8.dp))
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FlagChip("Healthy", candidate.healthy)
                    FlagChip("WebSocket", candidate.webSocketOk)
                    FlagChip("Stable", candidate.heldOpen)
                    FlagChip("TLS", candidate.tlsOk)
                }
            }

            if (candidate.notes.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                RockerCard {
                    SectionLabel("Why flagged")
                    Spacer(Modifier.height(8.dp))
                    candidate.notes.forEach { note ->
                        Text(
                            text = "• $note",
                            style = MaterialTheme.typography.bodySmall,
                            color = VerdictCaution,
                        )
                        Spacer(Modifier.height(4.dp))
                    }
                }
            }
        }
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("IP ROCKER", text))
}

private fun shareText(context: Context, text: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
        putExtra(Intent.EXTRA_SUBJECT, "IP ROCKER results")
    }
    context.startActivity(Intent.createChooser(intent, "Share IP list"))
}

/**
 * Writes text to a user-picked file via the storage access framework and returns
 * the resulting URI. Returns null if the user cancels the picker. Using SAF
 * (rather than a fixed path) avoids the scoped-storage restrictions on newer
 * Android and lets the user save working_ips.txt wherever they like.
 */
private fun saveTextFile(context: Context, fileName: String, text: String): android.net.Uri? {
    val resolver = context.contentResolver
    val values = android.content.ContentValues().apply {
        put(android.provider.MediaStore.Downloads.DISPLAY_NAME, fileName)
        put(android.provider.MediaStore.Downloads.MIME_TYPE, "text/plain")
    }
    val collection = android.provider.MediaStore.Downloads.getContentUri("external")
    val uri = resolver.insert(collection, values) ?: return null
    resolver.openOutputStream(uri)?.use { out ->
        out.write(text.toByteArray(Charsets.UTF_8))
    }
    return uri
}
