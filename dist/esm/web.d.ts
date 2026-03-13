/**
 * @file web.ts
 * @description Web implementation of the DeviceSecurityDetect plugin.
 * This implementation is limited due to the constraints of the web platform.
 */
import { WebPlugin } from '@capacitor/core';
import type { DeviceSecurityDetectPlugin } from './definitions';
/**
 * @class DeviceSecurityDetectWeb
 * @extends WebPlugin
 * @implements DeviceSecurityDetectPlugin
 *
 * Provides a fallback implementation for the web platform, where the functionality of this plugin is not supported.
 */
export declare class DeviceSecurityDetectWeb extends WebPlugin implements DeviceSecurityDetectPlugin {
    /**
     * Detect if the device is rooted or jailbroken.
     *
     * @returns A rejected promise indicating the method is unimplemented on the web.
     */
    isJailBreakOrRooted(): Promise<{
        value: boolean;
    }>;
    /**
     * Check if a password or PIN is enabled on the device.
     *
     * @returns A rejected promise indicating the method is unimplemented on the web.
     */
    pinCheck(): Promise<{
        value: boolean;
    }>;
    /**
     * Start continuous jailbreak monitoring.
     *
     * @returns A rejected promise indicating the method is unimplemented on the web.
     */
    startMonitoring(): Promise<void>;
    /**
   * Stop continuous jailbreak monitoring.
   *
   * @returns A rejected promise indicating the method is unimplemented on the web.
   */
    stopMonitoring(): Promise<void>;
    /**
     * Utility method to create an exception for unimplemented functionality.
     *
     * @returns {CapacitorException} An exception with an `Unimplemented` code and a descriptive message.
     */
    private createUnimplementedError;
}
