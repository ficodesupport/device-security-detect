/**
 * @file web.ts
 * @description Web implementation of the DeviceSecurityDetect plugin.
 * This implementation is limited due to the constraints of the web platform.
 */
import { CapacitorException, ExceptionCode, WebPlugin } from '@capacitor/core';
/**
 * @class DeviceSecurityDetectWeb
 * @extends WebPlugin
 * @implements DeviceSecurityDetectPlugin
 *
 * Provides a fallback implementation for the web platform, where the functionality of this plugin is not supported.
 */
export class DeviceSecurityDetectWeb extends WebPlugin {
    /**
     * Detect if the device is rooted or jailbroken.
     *
     * @returns A rejected promise indicating the method is unimplemented on the web.
     */
    async isJailBreakOrRooted() {
        console.warn('DeviceSecurityDetect: Method isJailBreakOrRooted is not supported on the web.');
        throw this.createUnimplementedError();
    }
    /**
     * Check if a password or PIN is enabled on the device.
     *
     * @returns A rejected promise indicating the method is unimplemented on the web.
     */
    async pinCheck() {
        console.warn('DeviceSecurityDetect: Method pinCheck is not supported on the web.');
        throw this.createUnimplementedError();
    }
    /**
     * Start continuous jailbreak monitoring.
     *
     * @returns A rejected promise indicating the method is unimplemented on the web.
     */
    async startMonitoring() {
        console.warn('DeviceSecurityDetect: Method startMonitoring is not supported on the web.');
        throw this.createUnimplementedError();
    }
    /**
     * Utility method to create an exception for unimplemented functionality.
     *
     * @returns {CapacitorException} An exception with an `Unimplemented` code and a descriptive message.
     */
    createUnimplementedError() {
        return new CapacitorException('DeviceSecurityDetect is not supported on the web.', ExceptionCode.Unimplemented);
    }
}
//# sourceMappingURL=web.js.map