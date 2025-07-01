package io.github.yoganataa.caster.app

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.yoganataa.caster.app.ui.theme.CasterTheme
import io.github.yoganataa.caster.core.Caster
import io.github.yoganataa.caster.core.CasterConfig
import io.github.yoganataa.caster.core.models.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.roundToInt

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CasterTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xFFF8F9FA)
                ) {
                    CasterScanScreen()
                }
            }
        }
    }
}

// Data class untuk UI State dan Device Info
data class SecurityUiState(
    val isScanning: Boolean = false,
    val scanResult: CasterResult? = null,
    val errorMessage: String? = null,
    val dialogToShow: DialogType = DialogType.None
)

enum class DialogType {
    None, Overall, Root, Emulator, FlagSecure, Malicious
}

data class DeviceInfo(
    val deviceName: String,
    val architecture: String,
    val osVersion: String,
    val kernel: String,
    val ramUsagePercent: Float,
    val ramTotal: String
)

// ViewModel
class SecurityViewModel : ViewModel() {
    private var caster: Caster? = null
    var uiState by mutableStateOf(SecurityUiState())
        private set

    fun initializeCaster() {
        if (caster != null) return
        try {
            caster = Caster(config = CasterConfig())
        } catch (e: Exception) {
            uiState = uiState.copy(errorMessage = "Initialization Failed: ${e.message}")
        }
    }

    fun startSecurityScan(activity: Activity) {
        if (caster == null) {
            uiState = uiState.copy(errorMessage = "Caster is not initialized.")
            return
        }
        viewModelScope.launch {
            uiState = uiState.copy(isScanning = true, errorMessage = null)
            try {
                val result = withContext(Dispatchers.IO) {
                    caster!!.analyze(activity)
                }
                uiState = uiState.copy(isScanning = false, scanResult = result)
            } catch (e: Exception) {
                uiState = uiState.copy(isScanning = false, errorMessage = "Scan failed: ${e.message}")
            }
        }
    }

    fun showDialog(type: DialogType) {
        uiState = uiState.copy(dialogToShow = type)
    }

    fun onDialogDismiss() {
        uiState = uiState.copy(dialogToShow = DialogType.None)
    }
}

// Main Screen
@Composable
fun CasterScanScreen(viewModel: SecurityViewModel = viewModel()) {
    val context = LocalContext.current
    val uiState = viewModel.uiState

    LaunchedEffect(Unit) {
        viewModel.initializeCaster()
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFFF8F9FA))
        ) {
            Text(
                text = "Caster Eyes",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF1A1A1A),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 36.dp, bottom = 16.dp),
                textAlign = TextAlign.Center
            )

            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp)
            ) {
                Spacer(modifier = Modifier.height(8.dp))
                when {
                    uiState.isScanning -> ScanningIndicator()
                    uiState.scanResult != null -> {
                        ScanResultContent(
                            result = uiState.scanResult,
                            context = context,
                            onRootClick = { viewModel.showDialog(DialogType.Root) },
                            onEmulatorClick = { viewModel.showDialog(DialogType.Emulator) },
                            onFlagSecureClick = { viewModel.showDialog(DialogType.FlagSecure) },
                            onMaliciousClick = { viewModel.showDialog(DialogType.Malicious) },
                            onOverallClick = { viewModel.showDialog(DialogType.Overall) }
                        )
                    }
                    else -> WelcomeMessage()
                }
                Spacer(modifier = Modifier.height(20.dp))
            }

            Column(modifier = Modifier.padding(20.dp)) {
                AnimatedVisibility(visible = uiState.errorMessage != null) {
                    ErrorCard(uiState.errorMessage ?: "")
                    Spacer(modifier = Modifier.height(16.dp))
                }
                ScanButton(
                    uiState = uiState,
                    onScanClick = {
                        (context as? Activity)?.let { viewModel.startSecurityScan(it) }
                    }
                )
            }
        }

        DialogHandler(uiState = uiState, onDismiss = viewModel::onDialogDismiss)
    }
}

@Composable
private fun ScanningIndicator() {
    Box(
        modifier = Modifier.fillMaxSize().padding(vertical = 100.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator(
                modifier = Modifier.size(64.dp),
                color = Color(0xFF4285F4),
                strokeWidth = 4.dp
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = "Scanning device...", fontSize = 16.sp, color = Color(0xFF5F6368))
        }
    }
}

@Composable
private fun WelcomeMessage() {
    Box(
        modifier = Modifier.fillMaxSize().padding(vertical = 100.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = "Tap the scan button to start device security analysis",
            textAlign = TextAlign.Center,
            fontSize = 16.sp,
            color = Color(0xFF5F6368),
            modifier = Modifier.padding(horizontal = 32.dp)
        )
    }
}

@Composable
private fun ErrorCard(errorMessage: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFFEBEE)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(imageVector = Icons.Default.Error, contentDescription = "Error", tint = Color(0xFFD32F2F))
            Spacer(modifier = Modifier.width(8.dp))
            Text(text = "Error: $errorMessage", color = Color(0xFFD32F2F), fontSize = 14.sp)
        }
    }
}

@Composable
private fun ScanButton(
    uiState: SecurityUiState,
    onScanClick: () -> Unit,
) {
    Button(
        onClick = onScanClick,
        enabled = !uiState.isScanning,
        modifier = Modifier.fillMaxWidth().height(56.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4285F4)),
        shape = RoundedCornerShape(16.dp)
    ) {
        Text(
            text = if (uiState.scanResult == null) "SCAN NOW" else "RE-SCAN",
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold,
            color = Color.White
        )
    }
}

@Composable
fun ScanResultContent(
    result: CasterResult,
    context: Context,
    onRootClick: () -> Unit,
    onEmulatorClick: () -> Unit,
    onFlagSecureClick: () -> Unit,
    onMaliciousClick: () -> Unit,
    onOverallClick: () -> Unit
) {
    Column {
        ScanResultGrid(
            result = result,
            onRootClick = onRootClick,
            onEmulatorClick = onEmulatorClick,
            onFlagSecureClick = onFlagSecureClick,
            onMaliciousClick = onMaliciousClick
        )
        Spacer(modifier = Modifier.height(20.dp))
        EnhancedDeviceInfoCard(context = context, onOverallClick = onOverallClick)
    }
}

@Composable
fun ScanResultGrid(
    result: CasterResult,
    onRootClick: () -> Unit,
    onEmulatorClick: () -> Unit,
    onFlagSecureClick: () -> Unit,
    onMaliciousClick: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            SecurityCard(
                title = "Root Status",
                icon = Icons.Default.Memory,
                statusText = if (result.rootResult.isRooted) "Detected" else "No",
                isSecure = !result.rootResult.isRooted,
                onClick = onRootClick,
                modifier = Modifier.weight(1f)
            )
            SecurityCard(
                title = "Emulator",
                icon = Icons.Default.PhoneAndroid,
                statusText = if (result.emulatorResult.isEmulator) "Detected" else "No",
                isSecure = !result.emulatorResult.isEmulator,
                onClick = onEmulatorClick,
                modifier = Modifier.weight(1f)
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            SecurityCard(
                title = "Flag Secure",
                icon = Icons.Default.VerifiedUser,
                statusText = if (!result.flagSecureResult.isFlagSecureDisabled) "Yes" else "Disabled",
                isSecure = !result.flagSecureResult.isFlagSecureDisabled,
                onClick = onFlagSecureClick,
                modifier = Modifier.weight(1f)
            )
            SecurityCard(
                title = "Malicious",
                icon = Icons.Default.BugReport,
                statusText = if (result.maliciousAppsResult.hasMaliciousApps) "Warning" else "Clean",
                isSecure = !result.maliciousAppsResult.hasMaliciousApps,
                onClick = onMaliciousClick,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
fun SecurityCard(
    title: String,
    icon: ImageVector,
    statusText: String,
    isSecure: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val statusColor = if (isSecure) Color(0xFF4CAF50) else Color(0xFFFF9800)
    val statusIcon = if (isSecure) Icons.Default.CheckCircle else Icons.Default.Cancel
    val cardColor = Color.White
    val mainIconColor = if (isSecure) Color(0xFF4285F4) else Color(0xFFFF9800)

    Card(
        modifier = modifier
            .clickable { onClick() }
            .aspectRatio(1f),
        colors = CardDefaults.cardColors(containerColor = cardColor),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.SpaceBetween,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = mainIconColor,
                modifier = Modifier.size(40.dp)
            )
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color(0xFF2E3A47),
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    Icon(
                        imageVector = statusIcon,
                        contentDescription = null,
                        tint = statusColor,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(text = statusText, fontSize = 12.sp, fontWeight = FontWeight.Medium, color = statusColor)
                }
            }
        }
    }
}

@Composable
fun EnhancedDeviceInfoCard(context: Context, onOverallClick: () -> Unit) {
    // PERBAIKAN: Memanggil `getRamInfo` bukan `getDeviceInfo` yang tidak ada.
    val deviceInfo = remember { getRamInfo(context) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Default.Smartphone,
                    contentDescription = "Device",
                    tint = Color(0xFF4285F4),
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    // PERBAIKAN: Menggunakan properti yang benar dari data class DeviceInfo
                    text = deviceInfo.deviceName,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF1A1A1A)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            DeviceSpec("Architecture", deviceInfo.architecture)
            DeviceSpec("OS Version", deviceInfo.osVersion)
            DeviceSpec("Kernel", deviceInfo.kernel)

            Spacer(modifier = Modifier.height(12.dp))

            Text("RAM", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF666666))
            Spacer(modifier = Modifier.height(4.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${deviceInfo.ramUsagePercent.roundToInt()}% used",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF2E3A47)
                )
                Text(
                    text = getRAMStatus(deviceInfo.ramUsagePercent),
                    fontSize = 12.sp,
                    color = getRAMStatusColor(deviceInfo.ramUsagePercent)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            val animatedProgress by animateFloatAsState(
                targetValue = deviceInfo.ramUsagePercent / 100f,
                animationSpec = tween(1000), label = "ramProgress"
            )
            // PERBAIKAN: Menggunakan lambda untuk parameter progress agar sesuai dengan Material 3
            LinearProgressIndicator(
                progress = { animatedProgress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(3.dp)),
                color = getRAMStatusColor(deviceInfo.ramUsagePercent),
                trackColor = Color(0xFFE0E0E0)
            )

            Spacer(modifier = Modifier.height(20.dp))

            OutlinedButton(
                onClick = onOverallClick,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF6c757d)),
            ) {
                Text(
                    text = "OVERALL RESULT",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
private fun DeviceSpec(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Text(text = label, fontSize = 14.sp, color = Color.Gray)
        Text(text = value, fontSize = 14.sp, color = Color(0xFF2E3A47), fontWeight = FontWeight.SemiBold, textAlign = TextAlign.End)
    }
}

@Composable
private fun DialogHandler(uiState: SecurityUiState, onDismiss: () -> Unit) {
    uiState.scanResult?.let { scanResult ->
        val dialogType = uiState.dialogToShow
        AnimatedVisibility(
            visible = dialogType != DialogType.None,
            enter = fadeIn(tween(150)),
            exit = fadeOut(tween(150))
        ) {
            when (dialogType) {
                DialogType.Overall -> OverallResultDialog(result = scanResult, onDismiss = onDismiss)
                DialogType.Root -> RootStatusDialog(rootResult = scanResult.rootResult, onDismiss = onDismiss)
                DialogType.Emulator -> EmulatorDetectionDialog(emulatorResult = scanResult.emulatorResult, onDismiss = onDismiss)
                DialogType.FlagSecure -> FlagSecureDialog(flagSecureResult = scanResult.flagSecureResult, onDismiss = onDismiss)
                DialogType.Malicious -> MaliciousAppsDialog(maliciousResult = scanResult.maliciousAppsResult, onDismiss = onDismiss)
                DialogType.None -> {}
            }
        }
    }
}

// Helper Functions
private fun getDeviceName(): String {
    val manufacturer = Build.MANUFACTURER.replaceFirstChar { it.uppercase() }
    val model = Build.MODEL
    return "$manufacturer $model"
}

// PERBAIKAN: Nama fungsi diubah menjadi `getRamInfo` agar sesuai dengan pemanggilan
private fun getRamInfo(context: Context): DeviceInfo {
    val memoryInfo = ActivityManager.MemoryInfo().also {
        (context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager).getMemoryInfo(it)
    }
    val totalMemory = memoryInfo.totalMem
    val usedMemory = totalMemory - memoryInfo.availMem
    val usedPercentage = ((usedMemory.toDouble() / totalMemory.toDouble()) * 100).toFloat()
    val totalGB = String.format("%.1f", totalMemory / (1024.0 * 1024.0 * 1024.0))

    return DeviceInfo(
        deviceName = getDeviceName(),
        architecture = Build.SUPPORTED_ABIS.firstOrNull() ?: "Unknown",
        osVersion = "Android ${Build.VERSION.RELEASE}",
        kernel = System.getProperty("os.version") ?: "Unknown",
        ramUsagePercent = usedPercentage,
        ramTotal = totalGB
    )
}

private fun getRAMStatus(percentage: Float): String {
    return when {
        percentage < 70 -> "Optimal"
        percentage < 90 -> "Good"
        else -> "High"
    }
}

private fun getRAMStatusColor(percentage: Float): Color {
    return when {
        percentage < 70 -> Color(0xFF4CAF50) // Green
        percentage < 90 -> Color(0xFFFF9800) // Orange
        else -> Color(0xFFD32F2F) // Red
    }
}