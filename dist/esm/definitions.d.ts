/**
 * @file definitions.ts
 * @description TypeScript type definitions for the DeviceSecurityDetect plugin.
 */
import type { PluginListenerHandle } from '@capacitor/core';
/**
 * @interface DeviceSecurityDetectPlugin
 * @description Defines the methods provided by the DeviceSecurityDetect plugin.
 */
export interface DeviceSecurityDetectPlugin {
    /**
     * Detect if the device has been rooted (Android) or jailbroken (iOS).
     *
     * This method provides a boolean value indicating whether the device
     * has been tampered with (e.g., by rooting or jailbreaking).
     *
     * @returns A promise that resolves to an object containing:
     * - `value`: A boolean indicating if the device is rooted or jailbroken.
     *
     * @example
     * ```typescript
     * const result = await DeviceSecurityDetect.isJailBreakOrRooted();
     * console.log(result.value); // true if rooted/jailbroken, false otherwise
     * ```
     * @since 6.0.0
     */
    isJailBreakOrRooted(): Promise<{
        value: boolean;
    }>;
    /**
     * Starts the native 2-minute polling loop for continuous jailbreak monitoring.
     * When a jailbreak is detected mid-session, the native side emits a
     * `jailbreakDetected` event that can be caught via `addListener`.
     *
     * @since 6.0.3
     */
    startMonitoring(): Promise<void>;
    /**
     * Registers a listener for native plugin events.
     *
     * Supported events:
     * - `jailbreakDetected`: Fired by the native polling loop when a jailbreak
     *   is detected after startup. Payload: `{ value: true }`.
     *
     * @param eventName - The name of the event to listen for.
     * @param listenerFunc - Callback invoked when the event is fired.
     * @returns A handle with a `remove()` method to unregister the listener.
     *
     * @since 6.0.3
     */
    addListener(eventName: 'jailbreakDetected', listenerFunc: (data: {
        value: boolean;
    }) => void): Promise<PluginListenerHandle>;
    /**
   * Stops the native 2-minute polling loop.
   * Call this when the app no longer needs continuous jailbreak monitoring.
   *
   * @since 6.0.3
   */
    stopMonitoring(): Promise<void>;
}
