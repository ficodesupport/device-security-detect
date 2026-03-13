import Foundation
import Capacitor

@objc(DeviceSecurityDetectPlugin)
public class DeviceSecurityDetectPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "DeviceSecurityDetectPlugin"
    public let jsName = "DeviceSecurityDetect"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "isJailBreakOrRooted", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "startMonitoring", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "stopMonitoring", returnType: CAPPluginReturnPromise)
    ]
    private let implementation = DeviceSecurityDetect()

    @objc func isJailBreakOrRooted(_ call: CAPPluginCall) {
        print("[DeviceSecurityDetectPlugin] Checking if device is jailbroken")
        call.resolve([
            "value": implementation.isJailBreak()
        ])
    }

    @objc func startMonitoring(_ call: CAPPluginCall) {
        implementation.startMonitoring {
            // Notify the JS layer via a plugin event when jailbreak is detected
            self.notifyListeners("jailbreakDetected", data: ["value": true])
        }
        call.resolve()
    }

    @objc func stopMonitoring(_ call: CAPPluginCall) {
        // Stop the native 2-minute polling timer
        implementation.stopMonitoring()
        call.resolve()
    }
}