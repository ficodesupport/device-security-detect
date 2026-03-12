import Foundation
import UIKit
import Darwin
import MachO

@objc public class DeviceSecurityDetect: NSObject {

    @objc public func isJailBreak() -> Bool {

        if isSimulator() {
            return false
        }

        if hasCydiaInstalled() {
            return true
        }

        if isContainsSuspiciousApps() {
            return true
        }

        if isSuspiciousSystemPathsExists() {
            return true
        }

        if canEditSystemFiles() {
            return true
        }

        if hasSuspiciousDyldImages() {
            return true
        }

        if isDebuggerAttached() {
            return true
        }

        if isFridaServerRunning() {
            return true
        }

        if hasSuspiciousEnvironmentVariables() {
            return true
        }

        return false
    }

    // MARK: - Simulator Check
    func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    // MARK: - Cydia URL Scheme
    // NOTE: Requires "cydia" in LSApplicationQueriesSchemes in Info.plist.
    // Unreliable on modern iOS — kept as a lightweight first signal only.
    func hasCydiaInstalled() -> Bool {
        if let url = URL(string: "cydia://package/com.example.package") {
            return UIApplication.shared.canOpenURL(url)
        }
        return false
    }

    // MARK: - Suspicious Apps
    func isContainsSuspiciousApps() -> Bool {
        for path in suspiciousAppsPathToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }

    // MARK: - Suspicious System Paths
    func isSuspiciousSystemPathsExists() -> Bool {
        for path in suspiciousSystemPathsToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }

    // MARK: - Sandbox Escape Check
    func canEditSystemFiles() -> Bool {
        let testPath = "/private/jailbreak_test.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }

    // MARK: - Injected Library Detection (Frida / Substrate / Shadow)
    // NOTE: String-name matching can be bypassed by renaming the dylib.
    // This is a first-pass heuristic; memory signature scanning adds depth.
    func hasSuspiciousDyldImages() -> Bool {
        let suspiciousLibraries = [
            "Frida",
            "FridaGadget",
            "FridaAgent",
            "SSLKillSwitch",
            "SSLKillSwitch2",
            "Substrate",
            "Shadow",
            "libhooker",
            "MobileSubstrate",
            "CydiaSubstrate"
        ]

        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                for lib in suspiciousLibraries {
                    if name.localizedCaseInsensitiveContains(lib) {
                        return true  // FIX: removed print() — leaks info in production
                    }
                }
            }
        }
        return false
    }

    // MARK: - Debugger Detection via sysctl
    func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

        let result = sysctl(&mib, 4, &info, &size, nil, 0)
        guard result == 0 else { return false }

        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    // MARK: - Frida Server Port Check
    // FIX: Moved inside the class (was a free function — caused compile error)
    func isFridaServerRunning() -> Bool {
        let ports: [UInt16] = [27042, 27043]

        for port in ports {
            var addr = sockaddr_in()
            addr.sin_len    = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port   = in_port_t(port).bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")

            let socketFD = socket(AF_INET, SOCK_STREAM, 0)
            guard socketFD >= 0 else { continue }

            let connected = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            close(socketFD)

            if connected == 0 {
                return true  // FIX: removed print() — leaks info in production
            }
        }
        return false
    }

    // MARK: - Environment Variable Check (NEW)
    // Frida and DYLD injection often rely on environment variables
    func hasSuspiciousEnvironmentVariables() -> Bool {
        let suspiciousKeys = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "FRIDA_"
        ]
        let env = ProcessInfo.processInfo.environment
        return suspiciousKeys.contains { key in
            env.keys.contains { $0.hasPrefix(key) }
        }
    }

    // MARK: - Suspicious Apps Path List
    // FIX: Added modern jailbreak paths (Dopamine / palera1n use /var/jb prefix)
    var suspiciousAppsPathToCheck: [String] {
        return [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/blackra1n.app",
            "/Applications/WinterBoard.app"
        ]
    }

    // MARK: - Suspicious System Path List
    // FIX: Added modern jailbreak paths (Dopamine / palera1n use /var/jb prefix)
    var suspiciousSystemPathsToCheck: [String] {
        return [
            // Classic paths
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/usr/bin/sshd",
            "/usr/sbin/sshd",
            "/usr/libexec/sftp-server",
            "/etc/apt",
            "/bin/bash",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/lib/libsubstitute.dylib",
            // Modern jailbreak paths (Dopamine, palera1n, etc.)
            "/var/jb/usr/bin/ssh",
            "/var/jb/usr/bin/sshd",
            "/var/jb/Library/MobileSubstrate",
            "/var/jb/usr/lib/libsubstitute.dylib",
            "/var/jb/etc/apt"
        ]
    }
}