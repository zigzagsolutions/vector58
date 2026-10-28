/** Product-wide constants. Values that differ per deployment belong in env config, not here. */
export const PRODUCT_NAME = 'Vector58 Browser Security';

/** Current PolicyPayload schema version emitted by the compiler. */
export const POLICY_SCHEMA_VERSION = 1;

/** Native messaging host name registered for Chrome and Edge. */
export const NATIVE_HOST_NAME = 'com.vector58.browser_security';

/** API namespace prefix. Breaking changes require a new major namespace. */
export const API_V1_PREFIX = '/api/v1';

/** Device credential header scheme: `Authorization: Device <deviceId>.<secret>`. */
export const DEVICE_AUTH_SCHEME = 'Device';

/** Heartbeat cadence expected from agents (seconds); drives offline detection. */
export const AGENT_HEARTBEAT_INTERVAL_SECONDS = 60;

/** A device is Offline when no heartbeat was seen for this many seconds. */
export const DEVICE_OFFLINE_AFTER_SECONDS = AGENT_HEARTBEAT_INTERVAL_SECONDS * 5;

/** Platform tenant-context sessions expire after this many minutes. */
export const TENANT_CONTEXT_TTL_MINUTES = 60;
