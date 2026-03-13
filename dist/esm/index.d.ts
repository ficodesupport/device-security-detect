/**
 * @file index.ts
 * @description Entry point for the DeviceSecurityDetect plugin.
 * This file defines the plugin's registration and export mechanisms.
 */
import type { DeviceSecurityDetectPlugin } from './definitions';
/**
 * Registers the `DeviceSecurityDetect` plugin.
 *
 * - The plugin name `DeviceSecurityDetect` is used to bridge native code with JavaScript.
 * - The web implementation is dynamically imported to optimize load times and performance for web environments.
 */
declare const DeviceSecurityDetect: DeviceSecurityDetectPlugin;
/**
 * Re-export the plugin type definitions for developer convenience.
 * This allows TypeScript users to access the `DeviceSecurityDetectPlugin` type.
 */
export * from './definitions';
/**
 * Exports the registered plugin as the default export.
 * Users can import and use `DeviceSecurityDetect` in their projects to call the plugin's methods.
 */
export { DeviceSecurityDetect };
