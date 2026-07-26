/**
 * PGP support (Flask source: app/pgp_utils.py), reimplemented on openpgp.js —
 * Workers has no GPG binary, no gnupg keyring and no sl-pgp/pgpy.
 *
 * Fingerprint format parity: Flask stores what gnupg's `import_keys(...)
 * .fingerprints[0]` returns — the primary key's fingerprint as UPPERCASE hex
 * (40 chars for v4 keys) with no spaces. openpgp.js `Key.getFingerprint()`
 * returns the same hex lowercased, so it is uppercased here before storage
 * in `mailbox.pgp_finger_print`.
 *
 * Deliberate deviations (vs app/pgp_utils.py):
 * - single implementation: the gnupg keyring path, the USE_RUST_PGP sl-pgp
 *   context and the pgpy fallback (encrypt_file_with_pgpy) collapse into one
 *   openpgp.js code path. PGPException remains the error type so callers keep
 *   Flask's error handling (load_public_key L61-75 / encrypt_file L117-190).
 * - encryptMessage takes the armored key directly instead of a fingerprint
 *   into a shared keyring (encrypt_file's mailbox/contact re-load dance
 *   L133-176 exists only because gnupg keyrings are per-host state; D1 always
 *   has the key next to the fingerprint).
 * - sign_data / sign_msg are not ported: PGP_SENDER_PRIVATE_KEY is not
 *   configured on this deployment and Flask only signs when it is set
 *   (email_handler.py L426 `if can_sign and config.PGP_SENDER_PRIVATE_KEY`).
 * - no NewRelic metrics / memory profiling.
 */

import * as openpgp from "openpgp";

/** app/pgp_utils.py PGPException L21-22. */
export class PGPException extends Error {}

/**
 * load_public_key (app/pgp_utils.py L61-75): parse an armored public key and
 * return the primary-key fingerprint, raising PGPException("Cannot load key")
 * on any parse failure.
 */
export async function loadPublicKey(publicKey: string): Promise<string> {
  try {
    const key = await openpgp.readKey({ armoredKey: publicKey });
    return key.getFingerprint().toUpperCase();
  } catch (e) {
    throw new PGPException("Cannot load key", { cause: e });
  }
}

/**
 * load_public_key_and_check (app/pgp_utils.py L78-107): load_public_key plus
 * a trial encryption of b"test"; a key that parses but cannot encrypt (e.g.
 * sign-only, expired or revoked) raises PGPException("Encryption fails with
 * the key"). Used by the mailbox-detail PGP save form.
 */
export async function loadPublicKeyAndCheck(
  publicKey: string,
): Promise<string> {
  let key: openpgp.Key;
  try {
    key = await openpgp.readKey({ armoredKey: publicKey });
  } catch (e) {
    throw new PGPException("Cannot load key", { cause: e });
  }
  try {
    await openpgp.encrypt({
      message: await openpgp.createMessage({
        binary: new TextEncoder().encode("test"),
      }),
      encryptionKeys: key,
    });
  } catch (e) {
    throw new PGPException("Encryption fails with the key", { cause: e });
  }
  return key.getFingerprint().toUpperCase();
}

/**
 * encrypt_file (app/pgp_utils.py L117-190): encrypt raw bytes (in the email
 * pipeline: a serialized inner MIME message) to the recipient's public key,
 * returning the ASCII-armored PGP message. gnupg's `always_trust=True` has no
 * analog (openpgp.js does not model keyring trust). Raises PGPException when
 * the key cannot be parsed or the encryption fails, matching the
 * "Cannot encrypt" error paths L176/L185.
 */
export async function encryptMessage(
  armoredKey: string,
  data: Uint8Array,
): Promise<string> {
  let key: openpgp.Key;
  try {
    key = await openpgp.readKey({ armoredKey });
  } catch (e) {
    throw new PGPException("Cannot load key", { cause: e });
  }
  try {
    const armored = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: data }),
      encryptionKeys: key,
    });
    return armored as string;
  } catch (e) {
    throw new PGPException(`Cannot encrypt: ${e}`, { cause: e });
  }
}
