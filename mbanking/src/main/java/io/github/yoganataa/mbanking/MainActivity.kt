package io.github.yoganataa.mbanking

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import io.github.yoganataa.mbanking.ui.theme.CasterTheme

class MainActivity : ComponentActivity() {

    private val viewModel: BankingViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        val splashScreen = installSplashScreen()
        super.onCreate(savedInstanceState)

        // Keep the splash screen visible while the ViewModel is loading.
        splashScreen.setKeepOnScreenCondition {
            viewModel.uiState.value.isLoading
        }

        // Start the root check as soon as the activity is created
        viewModel.startRootCheck(this)

        setContent {
            CasterTheme {
                val uiState by viewModel.uiState.collectAsState()

                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    if (uiState.isRooted) {
                        RootDetectedDialog(
                            onConfirm = {
                                // Close the app
                                finishAffinity()
                            }
                        )
                    } else if (!uiState.isLoading) {
                        // Only show the main screen if not loading and not rooted
                        BankingScreen()
                    }
                }
            }
        }
    }
}

@Composable
fun RootDetectedDialog(onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = { /* Do nothing, user must close the app */ },
        title = { Text(text = "Keamanan Terganggu") },
        text = { Text(text = "Aplikasi tidak dapat berjalan karena perangkat ini memiliki akses root. Demi keamanan data Anda, aplikasi akan ditutup.") },
        confirmButton = {
            Button(onClick = onConfirm) {
                Text("OK")
            }
        }
    )
}

@Composable
fun BankingScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Selamat Datang di M-Banking",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(24.dp))
        
        // Placeholder for banking info
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Saldo Anda:", style = MaterialTheme.typography.bodyLarge)
                Text("Rp 1.234.567", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.SemiBold)
            }
        }
        Spacer(modifier = Modifier.height(16.dp))
        Text("Transaksi Terakhir", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(8.dp))
        // Placeholder for transactions
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            TransactionItem("Transfer ke John Doe", "- Rp 50.000")
            TransactionItem("Pembayaran Listrik", "- Rp 120.000")
            TransactionItem("Gaji Masuk", "+ Rp 5.000.000")
        }
    }
}

@Composable
fun TransactionItem(description: String, amount: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = description, style = MaterialTheme.typography.bodyMedium)
        Text(text = amount, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
    }
}
