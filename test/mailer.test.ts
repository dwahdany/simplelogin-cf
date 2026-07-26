import { expect, it } from "vitest";
import { buildMime } from "../src/lib/mailer";

// SF-05: transactional From must be the Flask NOREPLY display-name form
// ("SimpleLogin (noreply)" <noreply@domain>), while the envelope sender (first
// arg) stays the bare address for the send_email binding's envelope==From rule.
it("uses the SimpleLogin (noreply) display name in the From header", () => {
  const raw = buildMime(
    "noreply@sl.example.com",
    '"SimpleLogin (noreply)" <noreply@sl.example.com>',
    { to: "u@example.com", subject: "Hi", text: "body" },
  );
  expect(raw).toContain(
    'From: "SimpleLogin (noreply)" <noreply@sl.example.com>',
  );
  expect(raw).toContain("To: u@example.com");
});
