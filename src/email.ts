/**
 * Email Routing worker: the forwarding/reply pipeline of spec
 * `specs/07-email-handling.md`.
 */

import type { Env } from "./lib/env";

export async function handleEmail(
  message: ForwardableEmailMessage,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  // TODO: implemented by the email-worker agent per specs/07-email-handling.md.
  void env;
  void ctx;
  message.setReject("Email handling not implemented yet");
}
