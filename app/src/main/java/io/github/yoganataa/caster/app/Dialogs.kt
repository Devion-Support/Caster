package io.github.yoganataa.caster.app

import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import coil3.compose.AsyncImage
import io.github.yoganataa.caster.core.models.*

// ===== Dialogs =====

@Composable
fun OverallResultDialog(result: CasterResult, onDismiss: () -> Unit) {
    BaseDialog(title = "OVERALL RESULT", onDismiss = onDismiss) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState())
        ) {
            OverallResultItem(
                icon = Icons.Default.Memory,
                title = "Root Status",
                status = if (result.rootResult.isRooted) result.rootResult.detectedMethods.firstOrNull()?.replaceFirstChar { it.uppercase() } ?: "Detected" else "No detection",
                isSecure = !result.rootResult.isRooted
            )
            OverallResultItem(
                icon = Icons.Default.PhoneAndroid,
                title = "Emulator",
                status = if (result.emulatorResult.isEmulator) "Detected" else "No detection",
                isSecure = !result.emulatorResult.isEmulator
            )
            OverallResultItem(
                icon = Icons.Default.VerifiedUser,
                title = "Flag Secure",
                status = if (!result.flagSecureResult.isFlagSecureDisabled) "Screen capture is restricted" else "Screen capture is possible",
                isSecure = !result.flagSecureResult.isFlagSecureDisabled
            )
            OverallResultItem(
                icon = Icons.Default.BugReport,
                title = "Malicious Apps",
                status = if (result.maliciousAppsResult.hasMaliciousApps) "${result.maliciousAppsResult.detectedApps.size} suspicious app(s) found" else "Clean",
                isSecure = !result.maliciousAppsResult.hasMaliciousApps
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
        ScoreIndicator(score = calculateSecurityScore(result))
    }
}

@Composable
fun RootStatusDialog(rootResult: RootResult, onDismiss: () -> Unit) {
    BaseDialog(title = "ROOT STATUS", icon = Icons.Default.Memory, onDismiss = onDismiss, isSecure = !rootResult.isRooted) {
        InfoRow(label = "Detected:", value = if (rootResult.isRooted) "Yes" else "No", isWarning = rootResult.isRooted)
        if (rootResult.isRooted) {
            InfoRow(label = "Confidence:", value = "${(rootResult.confidence * 100).toInt()}%", isWarning = true)
            InfoRow(
                label = "Method:",
                value = rootResult.detectedMethods.joinToString("\n").ifEmpty { "N/A" },
                isWarning = true
            )
        }
    }
}

@Composable
fun EmulatorDetectionDialog(emulatorResult: EmulatorResult, onDismiss: () -> Unit) {
    BaseDialog(title = "EMULATOR DETECTION", icon = Icons.Default.Gamepad, onDismiss = onDismiss, isSecure = !emulatorResult.isEmulator) {
        InfoRow(label = "Detected:", value = if (emulatorResult.isEmulator) "Yes" else "No", isWarning = emulatorResult.isEmulator)
        if (emulatorResult.isEmulator) {
            InfoRow(label = "Confidence:", value = "${(emulatorResult.confidence * 100).toInt()}%", isWarning = true)
            InfoRow(
                label = "Indicators:",
                value = "${emulatorResult.detectedMethods.size} found",
                isWarning = true
            )
        }
    }
}

@Composable
fun FlagSecureDialog(flagSecureResult: FlagSecureResult, onDismiss: () -> Unit) {
    BaseDialog(title = "FLAG SECURE", icon = Icons.Default.VerifiedUser, onDismiss = onDismiss, isSecure = !flagSecureResult.isFlagSecureDisabled) {
        InfoRow(label = "Protected:", value = if (!flagSecureResult.isFlagSecureDisabled) "Yes" else "No (Bypassed!)", isWarning = flagSecureResult.isFlagSecureDisabled)
        if (flagSecureResult.isFlagSecureDisabled) {
            InfoRow(label = "Bypass Method:", value = flagSecureResult.detectionMethods.joinToString("\n").ifEmpty { "N/A" }, isWarning = true)
        } else {
            InfoRow(label = "Status:", value = "Screen capture is restricted")
        }
    }
}

@Composable
fun MaliciousAppsDialog(maliciousResult: MaliciousAppsResult, onDismiss: () -> Unit) {
    BaseDialog(title = "MALICIOUS APPS", icon = Icons.Default.BugReport, onDismiss = onDismiss, isSecure = !maliciousResult.hasMaliciousApps) {
        if (maliciousResult.hasMaliciousApps) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                maliciousResult.detectedApps.forEach { app ->
                    MaliciousAppItem(packageName = app.packageName, appName = app.appName, riskLevel = app.riskLevel)
                }
            }
        } else {
            InfoRow(label = "Status:", value = "No malicious apps detected.")
        }
    }
}

// ===== Komponen UI Pendukung untuk Dialog =====

@Composable
private fun BaseDialog(
    title: String,
    icon: ImageVector? = null,
    onDismiss: () -> Unit,
    isSecure: Boolean = true,
    // PERBAIKAN: Menambahkan parameter content yang hilang, ini memperbaiki 3 error sekaligus.
    content: @Composable ColumnScope.() -> Unit
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        AnimatedVisibility(
            visible = true,
            enter = fadeIn(tween(300)) + scaleIn(tween(300), initialScale = 0.9f),
            exit = fadeOut(tween(200)) + scaleOut(tween(200), targetScale = 0.9f)
        ) {
            Card(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
            ) {
                Column(modifier = Modifier.padding(24.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        if (icon != null) {
                            val iconColor = if(isSecure) Color(0xFF4285F4) else Color(0xFFFF9800)
                            Icon(imageVector = icon, contentDescription = title, tint = iconColor, modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text(
                            text = title,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF2E3A47)
                        )
                    }
                    // PERBAIKAN: Mengganti Divider dengan HorizontalDivider yang tidak deprecated.
                    HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp), color = Color(0xFFF0F0F0))

                    content() // PERBAIKAN: Memanggil content lambda di sini

                    Spacer(modifier = Modifier.height(24.dp))
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4285F4)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("OK", fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }
            }
        }
    }
}

@Composable
fun InfoRow(label: String, value: String, isWarning: Boolean = false) {
    Row(modifier = Modifier.padding(bottom = 12.dp), verticalAlignment = Alignment.Top) {
        Text(
            text = label,
            modifier = Modifier.weight(0.4f),
            fontSize = 14.sp,
            fontWeight = FontWeight.Normal,
            color = Color.Gray
        )
        Text(
            text = value,
            modifier = Modifier.weight(0.6f),
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold,
            color = if (isWarning) Color(0xFFD32F2F) else Color.Black
        )
    }
}

@Composable
fun MaliciousAppItem(packageName: String, appName: String, riskLevel: String) {
    val context = LocalContext.current
    val appIcon: Drawable? = remember(packageName) {
        try {
            context.packageManager.getApplicationIcon(packageName)
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        // PERBAIKAN: Menggunakan AsyncImage untuk Coil v3
        AsyncImage(
            model = appIcon,
            contentDescription = "$appName icon",
            // Fallback jika ikon tidak ditemukan, tampilkan bug report
            error = rememberVectorPainter(image = Icons.Default.BugReport),
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(8.dp))
        )
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(text = appName, fontWeight = FontWeight.SemiBold, color = Color.Black)
            Text(text = riskLevel, color = Color(0xFFD32F2F), fontSize = 12.sp)
        }
    }
}

@Composable
fun OverallResultItem(icon: ImageVector, title: String, status: String, isSecure: Boolean) {
    Row(modifier = Modifier.padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        val iconColor = if (isSecure) Color(0xFF4285F4) else Color(0xFFFF9800)
        Icon(
            imageVector = icon,
            contentDescription = title,
            tint = iconColor,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, fontWeight = FontWeight.SemiBold)
            Text(text = status, color = Color.Gray, fontSize = 12.sp)
        }
        Icon(
            imageVector = if (isSecure) Icons.Default.CheckCircle else Icons.Default.Warning,
            contentDescription = if (isSecure) "Secure" else "Insecure",
            tint = if (isSecure) Color(0xFF388E3C) else Color(0xFFD32F2F)
        )
    }
}

@Composable
fun ScoreIndicator(score: Int) {
    val scoreColor = getScoreColor(score)
    val scoreText = when {
        score >= 80 -> "Excellent"
        score >= 60 -> "Good"
        score >= 40 -> "Fair"
        else -> "Poor"
    }
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(text = "Security Score", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            Text(text = "$score $scoreText", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = scoreColor)
        }
        Spacer(modifier = Modifier.height(8.dp))
        // PERBAIKAN: Menggunakan lambda untuk parameter progress
        LinearProgressIndicator(
            progress = { score / 100f },
            modifier = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)),
            color = scoreColor,
            trackColor = scoreColor.copy(alpha = 0.2f)
        )
    }
}

private fun calculateSecurityScore(result: CasterResult): Int {
    var score = 100
    if (result.rootResult.isRooted) score -= 30
    if (result.emulatorResult.isEmulator) score -= 20
    if (result.flagSecureResult.isFlagSecureDisabled) score -= 30
    if (result.maliciousAppsResult.hasMaliciousApps) score -= (result.maliciousAppsResult.detectedApps.size * 20)
    return score.coerceIn(0, 100)
}

@Composable
private fun getScoreColor(score: Int): Color {
    return when {
        score >= 80 -> Color(0xFF388E3C)
        score >= 60 -> Color(0xFFFBC02D)
        else -> Color(0xFFD32F2F)
    }
}