package io.github.yoganataa.caster.core.detection.tampering

import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType

/**
 * [DISESUAIKAN] Kelas untuk mendeteksi upaya tampering, hooking, dan debugging.
 * Strukturnya diubah agar sesuai dengan pola detektor Caster,
 * namun metode deteksi native tetap sama.
 */
class AntiTamperingDetector {

    companion object {
        init {
            try {
                // Memuat library native saat kelas pertama kali diakses
                System.loadLibrary("toolChecker")
            } catch (e: UnsatisfiedLinkError) {
                Logger.getInstance().error("Gagal memuat native library 'toolChecker' untuk AntiTampering", e)
            }
        }
    }

    /**
     * Hasil dari deteksi anti-tampering.
     */
    data class Result(
        val isDebuggerAttached: Boolean,
        val isHookingDetected: Boolean,
        val threats: List<ThreatInfo>,
        val detectedMethods: List<String>
    )

    /**
     * Fungsi utama untuk menjalankan semua pengecekan anti-tampering.
     * Menggabungkan semua logika deteksi ke dalam satu panggilan.
     */
    fun detect(): Result {
        val threats = mutableListOf<ThreatInfo>()
        val detectedMethods = mutableListOf<String>()
        var isDebuggerAttached = false
        var isHookingDetected = false

        try {
            if (checkForTracerPid() == 1) {
                val sign = "Debugger Attached (TracerPid > 0)"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.DEBUGGING, sign, "CRITICAL"))
                isDebuggerAttached = true
            }

            if (checkForHookingFrameworks() == 1) {
                val sign = "Hooking Framework Detected (frida/xposed in maps)"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.TAMPERING, sign, "CRITICAL"))
                isHookingDetected = true
            }

            if (checkForFridaPort() == 1) {
                val sign = "Frida Server Port (27042) is Open"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.TAMPERING, sign, "CRITICAL"))
                isHookingDetected = true // Terdeteksinya Frida juga merupakan indikasi hooking/tampering
            }
        } catch (t: Throwable) {
            Logger.getInstance().error("Error saat menjalankan deteksi native anti-tampering", t)
        }

        return Result(
            isDebuggerAttached = isDebuggerAttached,
            isHookingDetected = isHookingDetected,
            threats = threats,
            detectedMethods = detectedMethods.distinct()
        )
    }

    // ================================
    // Deklarasi Fungsi JNI Native
    // ================================
    private external fun checkForTracerPid(): Int
    private external fun checkForHookingFrameworks(): Int
    private external fun checkForFridaPort(): Int
}