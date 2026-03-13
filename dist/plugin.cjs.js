'use strict';

var core = require('@capacitor/core');

/**
 * @file index.ts
 * @description Entry point for the DeviceSecurityDetect plugin.
 * This file defines the plugin's registration and export mechanisms.
 */
/**
 * Registers the `DeviceSecurityDetect` plugin.
 *
 * - The plugin name `DeviceSecurityDetect` is used to bridge native code with JavaScript.
 * - The web implementation is dynamically imported to optimize load times and performance for web environments.
 */
const DeviceSecurityDetect = core.registerPlugin('DeviceSecurityDetect', {
    /**
     * Dynamic import of the web implementation.
     * This is used only when running in a web environment.
     *
     * @returns A promise that resolves to an instance of the `DeviceSecurityDetectWeb` class.
     */
    web: () => Promise.resolve().then(function () { return web; }).then((m) => new m.DeviceSecurityDetectWeb()),
});

/**
 * @file web.ts
 * @description Web implementation of the DeviceSecurityDetect plugin.
 * This implementation is limited due to the constraints of the web platform.
 */
/**
 * @class DeviceSecurityDetectWeb
 * @extends WebPlugin
 * @implements DeviceSecurityDetectPlugin
 *
 * Provides a fallback implementation for the web platform, where the functionality of this plugin is not supported.
 */
class DeviceSecurityDetectWeb extends core.WebPlugin {
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
   * Stop continuous jailbreak monitoring.
   *
   * @returns A rejected promise indicating the method is unimplemented on the web.
   */
    async stopMonitoring() {
        console.warn('DeviceSecurityDetect: Method stopMonitoring is not supported on the web.');
        throw this.createUnimplementedError();
    }
    /**
     * Utility method to create an exception for unimplemented functionality.
     *
     * @returns {CapacitorException} An exception with an `Unimplemented` code and a descriptive message.
     */
    createUnimplementedError() {
        return new core.CapacitorException('DeviceSecurityDetect is not supported on the web.', core.ExceptionCode.Unimplemented);
    }
}

var web = /*#__PURE__*/Object.freeze({
    __proto__: null,
    DeviceSecurityDetectWeb: DeviceSecurityDetectWeb
});

exports.DeviceSecurityDetect = DeviceSecurityDetect;
//# sourceMappingURL=plugin.cjs.js.map
