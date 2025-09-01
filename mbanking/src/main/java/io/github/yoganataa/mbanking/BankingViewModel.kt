package io.github.yoganataa.mbanking

import android.app.Activity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.yoganataa.caster.core.Caster
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class BankingUiState(
    val isLoading: Boolean = true,
    val isRooted: Boolean = false
)

class BankingViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(BankingUiState())
    val uiState = _uiState.asStateFlow()

    init {
        // The check starts as soon as the ViewModel is created.
        // In a real app, you might pass the activity context differently,
        // but for this sample, we'll require it to be passed to the check function.
    }

    fun startRootCheck(activity: Activity) {
        viewModelScope.launch {
            try {
                val caster = Caster.getInstance()
                val result = caster.analyze(activity)

                if (result.rootResult.isRooted) {
                    _uiState.value = BankingUiState(isLoading = false, isRooted = true)
                } else {
                    // Device is clean, proceed to the main screen
                    _uiState.value = BankingUiState(isLoading = false, isRooted = false)
                }
            } catch (e: Exception) {
                // Handle exceptions, maybe treat it as a non-rooted case for safety
                // or show a generic error. For this sample, we'll assume it's not rooted.
                _uiState.value = BankingUiState(isLoading = false, isRooted = false)
            }
        }
    }
}
