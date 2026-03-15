/**
 * SDK version, read from package.json at build time.
 * Read from package.json at build time.
 */
import pkg from "../package.json" with { type: "json" };

export const VERSION = pkg.version;
