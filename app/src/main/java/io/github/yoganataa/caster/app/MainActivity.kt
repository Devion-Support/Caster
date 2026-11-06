package io.github.yoganataa.caster.app

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.PrivacyTip
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Screenshot
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SmallTopAppBar
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.yoganataa.caster.Caster
import io.github.yoganataa.caster.models.CasterResult
import io.github.yoganataa.caster.ui.theme.CasterTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.roundToInt

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CasterTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    CasterScanScreen()
                }
            }
        }
    }
}

data class SecurityUiState(
    val isScanning: Boolean = false,
    val scanResult: CasterResult? = null,
    val errorMessage: String? = null
)

data class DeviceInfo(
    val deviceName: String,
    val architecture: String,
    val osVersion: String,
    val kernel: String,
    val ramUsagePercent: Float
)

class SecurityViewModel : ViewModel() {
    var uiState by mutableStateOf(SecurityUiState())
        private set

    fun startSecurityScan(activity: Activity) {
        if (uiState.isScanning) return

        viewModelScope.launch {
            uiState = uiState.copy(isScanning = true, errorMessage = null)
            runCatching {
                withContext(Dispatchers.IO) {
                    Caster.getInstance().analyze(activity)
                }
            }.onSuccess { result ->
                uiState = uiState.copy(isScanning = false, scanResult = result)
            }.onFailure { error ->
                uiState = uiState.copy(
                    isScanning = false,
                    errorMessage = error.message ?: "Security scan failed"
                )
            }
        }
    }
}

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun CasterScanScreen(viewModel: SecurityViewModel = viewModel()) {
    val context = LocalContext.current
    val state = viewModel.uiState
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            SmallTopAppBar(
                title = {
                    Column {
                        Text("Caster", fontWeight = FontWeight.SemiBold)
                        Text(
                            "Device security",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                navigationIcon = {
                    Icon(
                        Icons.Default.Shield,
                        contentDescription = null,
                        modifier = Modifier.padding(start = 16.dp)
                    )
                },
                scrollBehavior = scrollBehavior
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            when {
                state.isScanning -> ScanningState()
                state.scanResult == null -> WelcomeState()
                else -> Dashboard(result = state.scanResult, context = context)
            }

            ScanActions(
                state = state,
                context = context,
                onScan = viewModel::startSecurityScan,
                modifier = Modifier.align(Alignment.BottomCenter)
            )
        }
    }
}

@Composable
private fun ScanActions(
    state: SecurityUiState,
    context: Context,
    onScan: (Activity) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp)
    ) {
        state.errorMessage?.let {
            ErrorBanner(it)
            Spacer(Modifier.height(12.dp))
        }

        Button(
            onClick = { (context as? Activity)?.let(onScan) },
            enabled = !state.isScanning,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp)
        ) {
            Icon(
                Icons.Default.Security,
                contentDescription = null,
                modifier = Modifier.size(20.dp)
            )
            Spacer(Modifier.size(8.dp))
            Text(if (state.scanResult == null) "Run security scan" else "Run scan again")
        }
    }
}

@Composable
private fun WelcomeState() {
    Box(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                Icons.Default.Security,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(64.dp)
            )
            Spacer(Modifier.height(20.dp))
            Text(
                "Security posture",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(Modifier.height(8.dp))
            Text(
                "Run a local analysis to check root, integrity, tampering, emulator state and other security signals.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ScanningState() {
    Box(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            androidx.compose.material3.CircularProgressIndicator()
            Spacer(Modifier.height(20.dp))
            Text("Analyzing device", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                "Native detectors are running off the UI thread.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun Dashboard(result: CasterResult, context: Context) {
    val checks = securityChecks(result)
    val secure = checks.all { it.secure }
    val device = getDeviceInfo(context)

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 104.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { PostureHeader(secure = secure, checks = checks) }

        item {
            Text(
                "Security checks",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 8.dp, bottom = 2.dp)
            )
        }

        items(checks) { check ->
            SecurityCheckRow(check)
        }

        item { DeviceSection(device) }
    }
}

private data class SecurityCheck(
    val title: String,
    val summary: String,
    val secure: Boolean,
    val icon: ImageVector,
)

private fun securityChecks(result: CasterResult): List<SecurityCheck> = listOf(
    SecurityCheck(
        "Root",
        if (result.rootResult.isRooted) "Root access detected" else "No root indicators",
        !result.rootResult.isRooted,
        Icons.Default.Memory,
    ),
    SecurityCheck(
        "Emulator",
        if (result.emulatorResult.isEmulator) "Emulator indicators detected" else "Physical device indicators",
        !result.emulatorResult.isEmulator,
        Icons.Default.PhoneAndroid,
    ),
    SecurityCheck(
        "App integrity",
        if (result.integrityResult.isTampered) "Integrity anomalies detected" else "Integrity checks passed",
        !result.integrityResult.isTampered,
        Icons.Default.PrivacyTip,
    ),
    SecurityCheck(
        "Anti-tampering",
        if (
            result.tamperingResult.isDebuggerAttached ||
            result.tamperingResult.isHookingDetected
        ) {
            "Debugger or hooking detected"
        } else {
            "No tampering indicators"
        },
        !result.tamperingResult.isDebuggerAttached && !result.tamperingResult.isHookingDetected,
        Icons.Default.Warning,
    ),
    SecurityCheck(
        "Malicious apps",
        if (result.maliciousAppsResult.hasMaliciousApps) "Suspicious apps detected" else "No suspicious apps",
        !result.maliciousAppsResult.hasMaliciousApps,
        Icons.Default.BugReport,
    ),
    SecurityCheck(
        "Screen protection",
        if (result.flagSecureResult.isFlagSecureDisabled) "Protection is disabled" else "Protection is enabled",
        !result.flagSecureResult.isFlagSecureDisabled,
        Icons.Default.Screenshot,
    )
)

@Composable
private fun PostureHeader(secure: Boolean, checks: List<SecurityCheck>) {
    val failures = checks.count { !it.secure }
    val container = if (secure) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.errorContainer
    val content = if (secure) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onErrorContainer
    }

    Surface(
        color = container,
        contentColor = content,
        shape = RoundedCornerShape(28.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                if (secure) Icons.Default.CheckCircle else Icons.Default.Warning,
                contentDescription = null,
                modifier = Modifier.size(36.dp)
            )
            Spacer(Modifier.size(16.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    if (secure) "Secure posture" else "Attention required",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    if (secure) "No critical indicators were detected"
                    else "$failures of ${checks.size} checks need attention",
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
    }
}

@Composable
private fun SecurityCheckRow(check: SecurityCheck) {
    val color = if (check.secure) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error

    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        ListItem(
            headlineContent = { Text(check.title, fontWeight = FontWeight.Medium) },
            supportingContent = {
                Text(check.summary, color = MaterialTheme.colorScheme.onSurfaceVariant)
            },
            leadingContent = {
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer
                ) {
                    Icon(
                        check.icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.padding(10.dp)
                    )
                }
            },
            trailingContent = {
                Icon(
                    if (check.secure) Icons.Default.CheckCircle else Icons.Default.Warning,
                    contentDescription = null,
                    tint = color
                )
            }
        )
    }
}

@Composable
private fun DeviceSection(device: DeviceInfo) {
    Column {
        Text(
            "Device",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
        )

        Surface(
            color = MaterialTheme.colorScheme.surfaceContainer,
            shape = RoundedCornerShape(20.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(20.dp)) {
                Text(device.deviceName, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(12.dp))
                DeviceLine("Android", device.osVersion)
                DeviceLine("Architecture", device.architecture)
                DeviceLine("Kernel", device.kernel)
                Spacer(Modifier.height(12.dp))
                HorizontalDivider()
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("RAM usage", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("${device.ramUsagePercent.roundToInt()}%", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}

@Composable
private fun DeviceLine(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun ErrorBanner(message: String) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.Warning, contentDescription = null)
            Spacer(Modifier.size(10.dp))
            Text(message, style = MaterialTheme.typography.bodySmall)
        }
    }
}

private const val PERCENTAGE = 100.0

private fun getDeviceInfo(context: Context): DeviceInfo {
    val memoryInfo = ActivityManager.MemoryInfo()
    (context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager).getMemoryInfo(memoryInfo)
    val total = memoryInfo.totalMem.coerceAtLeast(1L)
    val used = total - memoryInfo.availMem
    val usage = (used.toDouble() / total.toDouble() * PERCENTAGE).toFloat()

    return DeviceInfo(
        deviceName = "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}",
        architecture = Build.SUPPORTED_ABIS.firstOrNull() ?: "Unknown",
        osVersion = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
        kernel = System.getProperty("os.version") ?: "Unknown",
        ramUsagePercent = usage
    )
}

