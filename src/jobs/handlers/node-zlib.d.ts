/**
 * Minimal ambient types for the node:zlib pieces used by send-user-report.ts.
 * The runtime implementation comes from workerd's `nodejs_compat`
 * (wrangler.jsonc compatibility_flags); the project deliberately does not
 * depend on @types/node (tsconfig types is workers-types only).
 */
declare module "node:zlib" {
  /** Raw-deflate a buffer synchronously (returns a Buffer, a Uint8Array). */
  export function deflateRawSync(data: Uint8Array): Uint8Array;
  /** Inverse of deflateRawSync; used by tests to unzip the report. */
  export function inflateRawSync(data: Uint8Array): Uint8Array;
}
