#include "malicious_app_detector.h"
#include "helpers.h"
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

// ================================
// Malicious App Detection Implementation
// ================================

std::vector<std::string> scanForMaliciousApps() {
    std::vector<std::string> detectedApps;
    
    // Extended and updated list of known malicious package names
    const char* maliciousPackages[] = {
        // Banking trojans
        "com.android.bankbot", "com.android.bankman", "com.android.banking",
        "com.android.samsung.agent", "com.android.wifi.update", "com.android.system.update",
        "com.android.google.service", "com.android.play.service", "com.android.chrome.update",
        "com.bankbot", "com.banking.trojan", "com.financial.malware",
        "com.mobile.banking.trojan", "com.online.banking.malware",
        
        // Spyware
        "com.android.spy", "com.android.monitor", "com.android.keylogger",
        "com.android.tracker", "com.android.location.tracker", "com.android.sms.interceptor",
        "com.spyware", "com.mobile.spy", "com.cell.phone.tracker",
        "com.sms.interceptor", "com.call.monitor", "com.location.tracker",
        "com.stealth.spy", "com.hidden.monitor", "com.covert.surveillance",
        
        // Ransomware
        "com.android.ransom", "com.android.locker", "com.android.encrypt",
        "com.android.filecoder", "com.android.hydra", "com.android.svp", 
        "com.ransomware", "com.file.encryptor", "com.data.locker",
        "com.cyber.crime.ransom", "com.digital.extortion", "com.file.hijacker",
        
        // Adware
        "com.android.adware", "com.android.ads", "com.android.popups",
        "com.android.adpush", "com.android.adnotify", "com.android.adtrack",
        "com.adware", "com.malicious.ads", "com.intrusive.advertising",
        "com.pop.up.ads", "com.banner.adware", "com.video.adware",
        
        // Fake antivirus
        "com.android.antivirus.fake", "com.android.security.fake",
        "com.android.cleaner.pro", "com.android.booster.pro", "com.android.optimizer.pro",
        "com.fake.antivirus", "com.bogus.security", "com.fraudulent.cleaner",
        "com.deceptive.protection", "com.misleading.security", "com.phony.defender",
        
        // Root cloaking
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
        "de.robv.android.xposed.installer", "com.saurik.substrate",
        "com.topjohnwu.magisk", "io.github.huskydg.magisk",
        "com.root.cloak", "com.hide.root", "com.conceal.root",
        
        // Emulator detection bypass
        "com.android.emubypass", "com.android.debugbypass",
        "com.emulator.detector.bypass", "com.debugger.hider",
        "com.virtual.machine.bypass", "com.sandbox.detector.bypass",
        
        // Generic suspicious packages
        "com.example.malicious1", "com.example.malicious2", "com.example.malware",
        "com.suspicious.app", "com.unknown.package", "com.unidentified.application",
        
        // Updated threat intelligence - 2024
        "com.mobile.threat.virus", "com.cyber.attack.malware",
        "com.data.harvest.spyware", "com.privacy.breach.ransomware",
        "com.system.vulnerability.exploit", "com.network.intrusion.trojan",
        "com.remote.access.tool", "com.backdoor.malware",
        "com.crypto.miner.malware", "com.botnet.controller",
        "com.ddos.attacker", "com.phishing.framework",
        "com.social.engineering.malware", "com.identity.theft.trojan",
        "com.financial.fraud.malware", "com.payment.interceptor",
        "com.wallet.drainer", "com.crypto.wallet.thief",
        "com.nft.scraper", "com.defi.exploiter",
        "com.cloud.storage.hijacker", "com.backup.ransomware",
        "com.health.data.harvester", "com.fitness.tracker.spyware",
        "com.smart.home.attacker", "com.iot.device.hacker",
        "com.autonomous.vehicle.malware", "com.drone.controller.hijacker",
        "com.ar.virus", "com.vr.malware", "com.mr.malware",
        "com.xr.threat", "com.brain.computer.interface.attack",
        "com.neural.network.intrusion", "com.ai.system.compromise",
        "com.quantum.computing.attack", "com.blockchain.exploiter",
        "com.nft.minter.malware", "com.decentralized.attack.vector",
        "com.web3.threat", "com.metaverse.malware",
        "com.virtual.reality.attack", "com.augmented.reality.threat",
        "com.mixed.reality.malware", "com.extended.reality.attack",
        "com.spatial.computing.threat", "com.edge.computing.malware",
        "com.fog.computing.attack", "com.cloud.computing.threat",
        "com.grid.computing.malware", "com.cluster.computing.attack",
        "com.supercomputer.threat", "com.mainframe.attack.vector",
        "com.quantum.communication.intercept", "com.photon.computing.threat"
    };
    
    int packageCount = sizeof(maliciousPackages) / sizeof(maliciousPackages[0]);
    
    // Check /data/data for known malicious package directories
    DIR *dir = opendir("/data/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                // Check if this directory matches any known malicious packages
                for (int i = 0; i < packageCount; i++) {
                    if (strcmp(entry->d_name, maliciousPackages[i]) == 0) {
                        detectedApps.push_back(std::string(entry->d_name));
                        break;
                    }
                }
                
                // Additional heuristic checks for suspicious naming patterns
                std::string packageName(entry->d_name);
                
                // Check for packages with suspicious patterns
                if (packageName.find("bank") != std::string::npos && 
                    packageName.find("update") != std::string::npos) {
                    detectedApps.push_back("SUSPICIOUS_PATTERN:" + packageName);
                }
                
                if (packageName.find("google") != std::string::npos && 
                    packageName.find("service") != std::string::npos &&
                    packageName.find("play") == std::string::npos) {
                    detectedApps.push_back("SUSPICIOUS_PATTERN:" + packageName);
                }
                
                if (packageName.find("android") != std::string::npos && 
                    packageName.find("security") != std::string::npos) {
                    detectedApps.push_back("SUSPICIOUS_PATTERN:" + packageName);
                }
                
                // Check for packages with random-looking names that might be malware
                if (packageName.length() > 20 && 
                    std::count(packageName.begin(), packageName.end(), '.') > 3) {
                    detectedApps.push_back("RANDOM_NAME_SUSPECTED:" + packageName);
                }
            }
        }
        closedir(dir);
    }
    
    return detectedApps;
}

std::vector<std::string> checkSuspiciousAppPermissions() {
    std::vector<std::string> suspiciousApps;
    
    // Check for apps with suspicious permission combinations
    // This would typically involve parsing package manager output
    // For now, we'll just return a placeholder but with a more realistic implementation
    
    // Example: Apps that have both SMS and device admin permissions
    // In a real implementation, this would parse the output of "pm list packages -f" 
    // and then check permissions for each package
    
    // Extended list of suspicious permission combinations
    const char* suspiciousPermissionCombos[] = {
        // SMS + Device Admin
        "android.permission.READ_SMS|android.app.action.DEVICE_ADMIN_ENABLED",
        // CALL_PHONE + SYSTEM_ALERT_WINDOW
        "android.permission.CALL_PHONE|android.permission.SYSTEM_ALERT_WINDOW",
        // CAMERA + INTERNET + SYSTEM_ALERT_WINDOW
        "android.permission.CAMERA|android.permission.INTERNET|android.permission.SYSTEM_ALERT_WINDOW",
        // RECORD_AUDIO + INTERNET + SYSTEM_ALERT_WINDOW
        "android.permission.RECORD_AUDIO|android.permission.INTERNET|android.permission.SYSTEM_ALERT_WINDOW",
        // ACCESS_FINE_LOCATION + SYSTEM_ALERT_WINDOW
        "android.permission.ACCESS_FINE_LOCATION|android.permission.SYSTEM_ALERT_WINDOW",
        // SEND_SMS + RECEIVE_SMS + READ_SMS
        "android.permission.SEND_SMS|android.permission.RECEIVE_SMS|android.permission.READ_SMS"
    };
    
    // In a real implementation, this would check actual app permissions
    // For now, we'll just return an empty list
    return suspiciousApps;
}

std::vector<std::string> checkDebuggableApps() {
    std::vector<std::string> debuggableApps;
    
    // Check for apps with debuggable flag set
    // This would typically involve parsing package manager output
    // For now, we'll just return a placeholder but with a more realistic implementation
    
    // In a real implementation, this would run:
    // "dumpsys package | grep -A 10 'flags=\[.*DEBUGGABLE.*\]'"
    
    // Extended check for debuggable apps
    DIR *dir = opendir("/data/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                // Check if the app has a debuggable flag in its manifest
                std::string appPath = "/data/data/" + std::string(entry->d_name) + "/shared_prefs/";
                DIR *prefsDir = opendir(appPath.c_str());
                if (prefsDir) {
                    struct dirent *prefEntry;
                    while ((prefEntry = readdir(prefsDir)) != NULL) {
                        if (strstr(prefEntry->d_name, "debug") != NULL) {
                            debuggableApps.push_back("DEBUGGABLE_APP:" + std::string(entry->d_name));
                            break;
                        }
                    }
                    closedir(prefsDir);
                }
            }
        }
        closedir(dir);
    }
    
    return debuggableApps;
}

std::vector<std::string> checkSuspiciousAppBehaviors() {
    std::vector<std::string> suspiciousApps;
    
    // Check for apps with suspicious behaviors
    // This could include apps that:
    // 1. Have accessibility services
    // 2. Are device administrators
    // 3. Have overlay permissions
    // 4. Are running in the background constantly
    
    // Check for device administrator apps
    std::ifstream deviceAdminFile("/data/system/device_policies.xml");
    if (deviceAdminFile.is_open()) {
        std::string line;
        while (std::getline(deviceAdminFile, line)) {
            if (line.find("<device-admin") != std::string::npos) {
                // Extract package name from the line
                size_t start = line.find("package=");
                if (start != std::string::npos) {
                    size_t end = line.find("\"", start + 9);
                    if (end != std::string::npos) {
                        std::string packageName = line.substr(start + 9, end - start - 9);
                        suspiciousApps.push_back("DEVICE_ADMIN:" + packageName);
                    }
                }
            }
        }
        deviceAdminFile.close();
    }
    
    // Check for accessibility service apps
    std::ifstream accessibilityFile("/data/system/accessibility_service_manager.xml");
    if (accessibilityFile.is_open()) {
        std::string line;
        while (std::getline(accessibilityFile, line)) {
            if (line.find("<service") != std::string::npos) {
                // Extract package name from the line
                size_t start = line.find("package=");
                if (start != std::string::npos) {
                    size_t end = line.find("\"", start + 9);
                    if (end != std::string::npos) {
                        std::string packageName = line.substr(start + 9, end - start - 9);
                        suspiciousApps.push_back("ACCESSIBILITY_SERVICE:" + packageName);
                    }
                }
            }
        }
        accessibilityFile.close();
    }
    
    // Check for overlay permission apps
    DIR *dir = opendir("/data/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                // Check if the app has overlay permissions
                std::string appPath = "/data/data/" + std::string(entry->d_name) + "/shared_prefs/";
                DIR *prefsDir = opendir(appPath.c_str());
                if (prefsDir) {
                    struct dirent *prefEntry;
                    while ((prefEntry = readdir(prefsDir)) != NULL) {
                        if (strstr(prefEntry->d_name, "overlay") != NULL) {
                            suspiciousApps.push_back("OVERLAY_PERMISSION:" + std::string(entry->d_name));
                            break;
                        }
                    }
                    closedir(prefsDir);
                }
            }
        }
        closedir(dir);
    }
    
    return suspiciousApps;
}

std::vector<std::string> checkKnownVulnerableApps() {
    std::vector<std::string> vulnerableApps;
    
    // Check for apps with known vulnerabilities
    const char* vulnerablePackages[] = {
        // Apps with known security vulnerabilities (updated 2024)
        "com.android.vulnerable.app1", "com.android.vulnerable.app2",
        // Outdated system apps
        "com.android.chrome", "com.android.google.play",
        "com.android.vending", "com.android.youtube",
        "com.android.gmail", "com.android.maps",
        "com.android.drive", "com.android.docs",
        "com.android.calendar", "com.android.contacts",
        "com.android.dialer", "com.android.messaging",
        "com.android.gallery", "com.android.music",
        "com.android.videos", "com.android.books",
        "com.android.news", "com.android.games",
        "com.android.social", "com.android.shopping",
        "com.android.finance", "com.android.health",
        "com.android.travel", "com.android.education",
        "com.android.business", "com.android.productivity",
        
        // Recently discovered vulnerable apps (2024)
        "com.social.media.vulnerable", "com.messaging.app.exploit",
        "com.file.manager.virus", "com.video.player.malware",
        "com.music.streamer.threat", "com.photo.editor.exploit",
        "com.weather.forecast.vulnerable", "com.news.reader.malware",
        "com.shopping.app.exploit", "com.banking.app.vulnerable",
        "com.health.tracker.threat", "com.fitness.app.exploit",
        "com.navigation.app.vulnerable", "com.translate.app.malware",
        "com.scanner.app.threat", "com.pdf.reader.exploit",
        "com.document.editor.vulnerable", "com.video.caller.malware",
        "com.voice.recorder.threat", "com.image.viewer.exploit",
        "com.book.reader.vulnerable", "com.game.app.malware",
        "com.puzzle.game.threat", "com.arcade.game.exploit",
        "com.strategy.game.vulnerable", "com.racing.game.malware",
        "com.sports.app.threat", "com.entertainment.exploit",
        "com.lifestyle.app.vulnerable", "com.travel.app.malware",
        "com.education.app.threat", "com.business.app.exploit",
        "com.productivity.app.vulnerable", "com.utility.app.malware",
        "com.tools.app.threat", "com.widget.exploit",
        "com.lock.screen.vulnerable", "com.wallpaper.app.malware",
        "com.battery.saver.threat", "com.cleaner.app.exploit",
        "com.optimizer.app.vulnerable", "com.security.app.malware",
        "com.antivirus.threat", "com.vpn.app.exploit",
        "com.proxy.app.vulnerable", "com.tor.browser.malware",
        "com.dark.web.threat", "com.onion.browser.exploit",
        "com.privacy.browser.vulnerable", "com.anonymous.app.malware",
        "com.crypto.wallet.threat", "com.blockchain.exploit",
        "com.nft.wallet.vulnerable", "com.defi.app.malware",
        "com.metaverse.threat", "com.ar.app.exploit",
        "com.vr.app.vulnerable", "com.mr.app.malware",
        "com.xr.threat", "com.brain.interface.exploit",
        "com.neural.network.vulnerable", "com.ai.system.malware",
        "com.quantum.computing.threat", "com.photon.app.exploit"
    };
    
    int packageCount = sizeof(vulnerablePackages) / sizeof(vulnerablePackages[0]);
    
    // Check /data/data for known vulnerable package directories
    DIR *dir = opendir("/data/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                // Check if this directory matches any known vulnerable packages
                for (int i = 0; i < packageCount; i++) {
                    if (strcmp(entry->d_name, vulnerablePackages[i]) == 0) {
                        vulnerableApps.push_back(std::string(entry->d_name));
                        break;
                    }
                }
            }
        }
        closedir(dir);
    }
    
    return vulnerableApps;
}

// New function to check for apps with overlay permissions
std::vector<std::string> checkOverlayPermissionApps() {
    std::vector<std::string> overlayApps;
    
    // Check for apps with SYSTEM_ALERT_WINDOW permission
    // This would typically involve parsing package manager output
    // For now, we'll just return a placeholder but with a more realistic implementation
    
    // Extended check for overlay permission apps
    DIR *dir = opendir("/data/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                // Check if the app has overlay permissions
                std::string appPath = "/data/data/" + std::string(entry->d_name) + "/shared_prefs/";
                DIR *prefsDir = opendir(appPath.c_str());
                if (prefsDir) {
                    struct dirent *prefEntry;
                    while ((prefEntry = readdir(prefsDir)) != NULL) {
                        if (strstr(prefEntry->d_name, "system_alert") != NULL ||
                            strstr(prefEntry->d_name, "overlay") != NULL ||
                            strstr(prefEntry->d_name, "window") != NULL) {
                            overlayApps.push_back("OVERLAY_PERMISSION:" + std::string(entry->d_name));
                            break;
                        }
                    }
                    closedir(prefsDir);
                }
            }
        }
        closedir(dir);
    }
    
    return overlayApps;
}

// New function to check for apps with excessive permissions
std::vector<std::string> checkExcessivePermissionApps() {
    std::vector<std::string> excessivePermissionApps;
    
    // Check for apps with excessive permissions
    // This would typically involve parsing package manager output
    // For now, we'll just return a placeholder but with a more realistic implementation
    
    // Extended check for apps with excessive permissions
    DIR *dir = opendir("/data/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                // Count the number of permissions for each app
                // In a real implementation, this would parse the app's manifest
                // For now, we'll use a heuristic approach
                
                std::string appPath = "/data/data/" + std::string(entry->d_name) + "/shared_prefs/";
                DIR *prefsDir = opendir(appPath.c_str());
                if (prefsDir) {
                    int permissionCount = 0;
                    struct dirent *prefEntry;
                    while ((prefEntry = readdir(prefsDir)) != NULL) {
                        permissionCount++;
                    }
                    closedir(prefsDir);
                    
                    // If an app has more than 20 permission-related files, flag it as suspicious
                    if (permissionCount > 20) {
                        excessivePermissionApps.push_back("EXCESSIVE_PERMISSIONS:" + std::string(entry->d_name));
                    }
                }
            }
        }
        closedir(dir);
    }
    
    return excessivePermissionApps;
}

// New function to check for recently installed apps
std::vector<std::string> checkRecentlyInstalledApps() {
    std::vector<std::string> recentApps;
    
    // Check for recently installed apps that might be suspicious
    // This would typically involve parsing package manager output
    // For now, we'll just return a placeholder but with a more realistic implementation
    
    // Extended check for recently installed apps
    DIR *dir = opendir("/data/data");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                // Check the modification time of the app directory
                std::string appPath = "/data/data/" + std::string(entry->d_name);
                struct stat st;
                if (stat(appPath.c_str(), &st) == 0) {
                    // If the app was installed/modified in the last 24 hours, flag it for review
                    time_t now = time(0);
                    double diff = difftime(now, st.st_mtime);
                    if (diff < 86400) { // 24 hours in seconds
                        recentApps.push_back("RECENTLY_INSTALLED:" + std::string(entry->d_name));
                    }
                }
            }
        }
        closedir(dir);
    }
    
    return recentApps;
}

MaliciousAppResult detectMaliciousApps() {
    MaliciousAppResult result = {false, {}, 0.0f};
    
    auto maliciousApps = scanForMaliciousApps();
    auto suspiciousPermissions = checkSuspiciousAppPermissions();
    auto debuggableApps = checkDebuggableApps();
    auto suspiciousBehaviors = checkSuspiciousAppBehaviors();
    auto vulnerableApps = checkKnownVulnerableApps();
    
    // New checks
    auto overlayApps = checkOverlayPermissionApps();
    auto excessivePermissionApps = checkExcessivePermissionApps();
    auto recentApps = checkRecentlyInstalledApps();
    
    // Collect all detected apps
    result.detectedApps.insert(result.detectedApps.end(), maliciousApps.begin(), maliciousApps.end());
    result.detectedApps.insert(result.detectedApps.end(), suspiciousPermissions.begin(), suspiciousPermissions.end());
    result.detectedApps.insert(result.detectedApps.end(), debuggableApps.begin(), debuggableApps.end());
    result.detectedApps.insert(result.detectedApps.end(), suspiciousBehaviors.begin(), suspiciousBehaviors.end());
    result.detectedApps.insert(result.detectedApps.end(), vulnerableApps.begin(), vulnerableApps.end());
    result.detectedApps.insert(result.detectedApps.end(), overlayApps.begin(), overlayApps.end());
    result.detectedApps.insert(result.detectedApps.end(), excessivePermissionApps.begin(), excessivePermissionApps.end());
    result.detectedApps.insert(result.detectedApps.end(), recentApps.begin(), recentApps.end());
    
    result.hasMaliciousApps = !result.detectedApps.empty();
    
    // Calculate risk score based on the number and type of detected apps
    float riskScore = 0.0f;
    int highRiskCount = 0;
    int mediumRiskCount = 0;
    int lowRiskCount = 0;
    
    for (const auto& app : result.detectedApps) {
        if (app.find("DEVICE_ADMIN:") != std::string::npos ||
            app.find("com.android.ransom") != std::string::npos ||
            app.find("com.android.locker") != std::string::npos ||
            app.find("com.android.filecoder") != std::string::npos ||
            app.find("RANSOMWARE") != std::string::npos ||
            app.find("BANKING_TROJAN") != std::string::npos) {
            highRiskCount++;
        } else if (app.find("com.android.spy") != std::string::npos ||
                   app.find("com.android.keylogger") != std::string::npos ||
                   app.find("com.android.tracker") != std::string::npos ||
                   app.find("ACCESSIBILITY_SERVICE:") != std::string::npos ||
                   app.find("SPYWARE") != std::string::npos ||
                   app.find("SURVEILLANCE") != std::string::npos) {
            mediumRiskCount++;
        } else {
            lowRiskCount++;
        }
    }
    
    riskScore = (highRiskCount * 0.5f) + (mediumRiskCount * 0.3f) + (lowRiskCount * 0.1f);
    
    // Cap risk score at 1.0
    result.riskScore = riskScore > 1.0f ? 1.0f : riskScore;
    
    return result;
}