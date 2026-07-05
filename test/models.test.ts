import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { addDays, toStr } from "../src/lib/dates";
import {
  aliasMailboxIds,
  availableSlEmail,
  canCreateNewAlias,
  defaultRandomAliasDomain,
  getPremiumInputs,
  getSLDomains,
  inTrial,
  isPremium,
  maxAliasForFreeAccount,
  type PremiumInputs,
  userInTrial,
  userIsPremium,
  userVerifiedMailboxes,
} from "../src/lib/models";
import type { SubscriptionRow } from "../src/lib/rows";
import {
  createAlias,
  createContact,
  createMailbox,
  createUser,
} from "./fixtures";

const NOW = new Date("2024-06-01T12:00:00Z");

/** minimal PremiumInputs with everything off. */
function emptyInputs(over: Partial<PremiumInputs> = {}): PremiumInputs {
  return {
    lifetime: false,
    trialEnd: null,
    paddle: null,
    apple: null,
    manual: null,
    coinbase: null,
    partner: null,
    ...over,
  };
}

function paddle(next_bill_date: string, cancelled = false): SubscriptionRow {
  return {
    id: 1,
    created_at: toStr(NOW),
    updated_at: null,
    cancel_url: "c",
    update_url: "u",
    subscription_id: "sub",
    event_time: toStr(NOW),
    next_bill_date,
    cancelled: cancelled ? 1 : 0,
    plan: "monthly",
    user_id: 1,
  };
}

describe("isPremium (pure precedence & grace)", () => {
  it("lifetime is always premium", () => {
    expect(isPremium(emptyInputs({ lifetime: true }), NOW)).toBe(true);
  });

  it("trial: premium while now < trial_end, not after", () => {
    expect(
      isPremium(emptyInputs({ trialEnd: toStr(addDays(NOW, 1)) }), NOW),
    ).toBe(true);
    expect(
      isPremium(emptyInputs({ trialEnd: toStr(addDays(NOW, -1)) }), NOW),
    ).toBe(false);
  });

  it("paddle active up to next_bill_date + 14 days (date granularity)", () => {
    // now - 14d = 2024-05-18 -> equal is still active
    expect(isPremium(emptyInputs({ paddle: paddle("2024-05-18") }), NOW)).toBe(
      true,
    );
    // now - 15d = 2024-05-17 -> expired
    expect(isPremium(emptyInputs({ paddle: paddle("2024-05-17") }), NOW)).toBe(
      false,
    );
    // future bill date -> active
    expect(isPremium(emptyInputs({ paddle: paddle("2024-07-01") }), NOW)).toBe(
      true,
    );
  });

  it("cancelled paddle still counts within grace", () => {
    expect(
      isPremium(emptyInputs({ paddle: paddle("2024-05-20", true) }), NOW),
    ).toBe(true);
  });

  it("apple valid while expires_date > now - 16 days", () => {
    const mk = (expires_date: string) => ({
      id: 1,
      created_at: toStr(NOW),
      updated_at: null,
      user_id: 1,
      expires_date,
      original_transaction_id: "t",
      receipt_data: "r",
      plan: "monthly" as const,
      product_id: null,
    });
    expect(
      isPremium(emptyInputs({ apple: mk("2024-05-16 12:00:01+00:00") }), NOW),
    ).toBe(true);
    expect(
      isPremium(emptyInputs({ apple: mk("2024-05-16 12:00:00+00:00") }), NOW),
    ).toBe(false);
  });

  it("manual/coinbase active while end_at > now", () => {
    const manual = {
      id: 1,
      created_at: toStr(NOW),
      updated_at: null,
      user_id: 1,
      end_at: toStr(addDays(NOW, 1)),
      comment: null,
      is_giveaway: 0,
    };
    expect(isPremium(emptyInputs({ manual }), NOW)).toBe(true);
    manual.end_at = toStr(addDays(NOW, -1));
    expect(isPremium(emptyInputs({ manual }), NOW)).toBe(false);

    const coinbase = {
      id: 1,
      created_at: toStr(NOW),
      updated_at: null,
      user_id: 1,
      end_at: toStr(addDays(NOW, 1)),
      code: null,
    };
    expect(isPremium(emptyInputs({ coinbase }), NOW)).toBe(true);
  });

  it("partner: lifetime or end_at within 14 days; excludable", () => {
    const lifetime = {
      id: 1,
      created_at: toStr(NOW),
      updated_at: null,
      partner_user_id: 1,
      end_at: null,
      lifetime: 1,
    };
    expect(isPremium(emptyInputs({ partner: lifetime }), NOW)).toBe(true);
    // excluded when include_partner=false
    expect(isPremium(emptyInputs({ partner: lifetime }), NOW, false)).toBe(
      false,
    );

    const grace = {
      ...lifetime,
      lifetime: 0,
      end_at: toStr(addDays(NOW, -13)),
    };
    expect(isPremium(emptyInputs({ partner: grace }), NOW)).toBe(true);
    const expired = { ...grace, end_at: toStr(addDays(NOW, -15)) };
    expect(isPremium(emptyInputs({ partner: expired }), NOW)).toBe(false);
  });
});

describe("inTrial", () => {
  it("simple form: trial_end set and now < trial_end", () => {
    const base = { trial_end: toStr(addDays(NOW, 3)) } as any;
    expect(inTrial(base, NOW)).toBe(true);
    expect(inTrial({ trial_end: null } as any, NOW)).toBe(false);
    expect(inTrial({ trial_end: toStr(addDays(NOW, -1)) } as any, NOW)).toBe(
      false,
    );
  });

  it("userInTrial is false when a subscription is active even if trial_end is future", async () => {
    const user = await createUser(env.DB, {
      trial_end: toStr(addDays(NOW, 5)),
    });
    expect(await userInTrial(env.DB, user, NOW)).toBe(true);

    await env.DB.prepare(
      "INSERT INTO manual_subscription (user_id, end_at, is_giveaway) VALUES (?1, ?2, 0)",
    )
      .bind(user.id, toStr(addDays(NOW, 30)))
      .run();
    expect(await userInTrial(env.DB, user, NOW)).toBe(false);
    // still premium via subscription
    expect(await userIsPremium(env.DB, user, NOW)).toBe(true);
  });
});

describe("getPremiumInputs / userIsPremium via DB", () => {
  it("loads subscription rows and evaluates premium", async () => {
    const user = await createUser(env.DB, { trial_end: null });
    let inputs = await getPremiumInputs(env.DB, user.id);
    expect(inputs.paddle).toBeNull();
    expect(isPremium(inputs, NOW)).toBe(false);

    await env.DB.prepare(
      `INSERT INTO subscription (cancel_url, update_url, subscription_id, event_time, next_bill_date, cancelled, plan, user_id)
       VALUES ('c','u','s',?1,?2,0,'yearly',?3)`,
    )
      .bind(toStr(NOW), "2024-07-01", user.id)
      .run();
    inputs = await getPremiumInputs(env.DB, user.id);
    expect(inputs.paddle?.plan).toBe("yearly");
    expect(isPremium(inputs, NOW)).toBe(true);
  });
});

describe("maxAliasForFreeAccount", () => {
  it("defaults to MAX_NB_EMAIL_FREE_PLAN, 15 for the old-limit flag", () => {
    const env5 = { MAX_NB_EMAIL_FREE_PLAN: "5" } as any;
    expect(maxAliasForFreeAccount({ flags: 1 } as any, env5)).toBe(5);
    // FLAG_FREE_OLD_ALIAS_LIMIT = 4
    expect(maxAliasForFreeAccount({ flags: 1 | 4 } as any, env5)).toBe(15);
    // unparseable env -> fallback 5
    expect(
      maxAliasForFreeAccount(
        { flags: 0 } as any,
        { MAX_NB_EMAIL_FREE_PLAN: "" } as any,
      ),
    ).toBe(5);
  });
});

describe("canCreateNewAlias", () => {
  it("free user: allowed under the limit, blocked at it; trashed excluded", async () => {
    const testEnv = { ...env, MAX_NB_EMAIL_FREE_PLAN: "2" } as any;
    const user = await createUser(env.DB, { trial_end: null });
    expect(await canCreateNewAlias(env.DB, testEnv, user, NOW)).toBe(true);

    await createAlias(env.DB, user.id, user.default_mailbox_id!);
    await createAlias(env.DB, user.id, user.default_mailbox_id!);
    // 2 aliases, limit 2 -> 2 + 1 > 2 -> blocked
    expect(await canCreateNewAlias(env.DB, testEnv, user, NOW)).toBe(false);

    // a pre-trashed alias does not count towards the limit
    await createAlias(env.DB, user.id, user.default_mailbox_id!, {
      delete_on: toStr(addDays(NOW, 30)),
    });
    expect(await canCreateNewAlias(env.DB, testEnv, user, NOW)).toBe(false); // still 2 active

    // trashing one active alias frees a slot
    const row = await env.DB.prepare(
      "SELECT id FROM alias WHERE user_id = ?1 AND delete_on IS NULL LIMIT 1",
    )
      .bind(user.id)
      .first<{ id: number }>();
    await env.DB.prepare("UPDATE alias SET delete_on = ?1 WHERE id = ?2")
      .bind(toStr(addDays(NOW, 30)), row!.id)
      .run();
    expect(await canCreateNewAlias(env.DB, testEnv, user, NOW)).toBe(true);
  });

  it("premium user is always allowed; disabled/inactive blocked", async () => {
    const testEnv = { ...env, MAX_NB_EMAIL_FREE_PLAN: "0" } as any;
    const user = await createUser(env.DB, { trial_end: null, lifetime: 1 });
    expect(await canCreateNewAlias(env.DB, testEnv, user, NOW)).toBe(true);

    const disabled = await createUser(env.DB, { trial_end: null, disabled: 1 });
    expect(await canCreateNewAlias(env.DB, testEnv, disabled, NOW)).toBe(false);

    const inactive = await createUser(env.DB, {
      trial_end: null,
      delete_on: toStr(addDays(NOW, 5)),
    });
    expect(await canCreateNewAlias(env.DB, testEnv, inactive, NOW)).toBe(false);
  });
});

describe("availableSlEmail", () => {
  it("false if used by an alias, a contact reply_email, or a deleted_alias", async () => {
    const user = await createUser(env.DB);
    expect(await availableSlEmail(env.DB, "fresh@sl.test")).toBe(true);

    const alias = await createAlias(env.DB, user.id, user.default_mailbox_id!, {
      email: "taken@sl.test",
    });
    expect(await availableSlEmail(env.DB, "taken@sl.test")).toBe(false);

    await createContact(env.DB, user.id, alias.id, {
      reply_email: "reply-used@sl.test",
    });
    expect(await availableSlEmail(env.DB, "reply-used@sl.test")).toBe(false);

    await env.DB.prepare(
      "INSERT INTO deleted_alias (email, reason) VALUES (?1, 0)",
    )
      .bind("gone@sl.test")
      .run();
    expect(await availableSlEmail(env.DB, "gone@sl.test")).toBe(false);
  });
});

describe("getSLDomains", () => {
  it("excludes hidden and premium_only for free users, ordered by 'order'", async () => {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO public_domain (domain, premium_only, hidden, "order") VALUES ('b.test',0,0,2)`,
      ),
      env.DB.prepare(
        `INSERT INTO public_domain (domain, premium_only, hidden, "order") VALUES ('a.test',0,0,1)`,
      ),
      env.DB.prepare(
        `INSERT INTO public_domain (domain, premium_only, hidden, "order") VALUES ('premium.test',1,0,3)`,
      ),
      env.DB.prepare(
        `INSERT INTO public_domain (domain, premium_only, hidden, "order") VALUES ('hidden.test',0,1,4)`,
      ),
    ]);
    const free = await createUser(env.DB, { trial_end: null });
    const freeDomains = (await getSLDomains(env.DB, free, env, NOW)).map(
      (d) => d.domain,
    );
    expect(freeDomains).toEqual(["a.test", "b.test"]);

    const premium = await createUser(env.DB, { trial_end: null, lifetime: 1 });
    const premiumDomains = (await getSLDomains(env.DB, premium, env, NOW)).map(
      (d) => d.domain,
    );
    expect(premiumDomains).toEqual(["a.test", "b.test", "premium.test"]);
  });
});

describe("defaultRandomAliasDomain", () => {
  it("uses a verified custom domain, else public domain, else FIRST_ALIAS_DOMAIN", async () => {
    const testEnv = {
      ...env,
      FIRST_ALIAS_DOMAIN: "first.test",
      EMAIL_DOMAIN: "sl.test",
    } as any;
    const user = await createUser(env.DB, { trial_end: null });
    expect(await defaultRandomAliasDomain(env.DB, user, testEnv, NOW)).toBe(
      "first.test",
    );

    const cd = await env.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain, verified) VALUES (?1,'mydomain.test',1) RETURNING id",
    )
      .bind(user.id)
      .first<{ id: number }>();
    await env.DB.prepare(
      "UPDATE users SET default_alias_custom_domain_id = ?1 WHERE id = ?2",
    )
      .bind(cd!.id, user.id)
      .run();
    const withCd = { ...user, default_alias_custom_domain_id: cd!.id };
    expect(await defaultRandomAliasDomain(env.DB, withCd, testEnv, NOW)).toBe(
      "mydomain.test",
    );

    // public domain, premium-only, non-premium user -> falls back and resets
    const pd = await env.DB.prepare(
      `INSERT INTO public_domain (domain, premium_only) VALUES ('pub.test',1) RETURNING id`,
    ).first<{ id: number }>();
    const pubUser = await createUser(env.DB, { trial_end: null });
    await env.DB.prepare(
      "UPDATE users SET default_alias_public_domain_id = ?1 WHERE id = ?2",
    )
      .bind(pd!.id, pubUser.id)
      .run();
    const withPub = { ...pubUser, default_alias_public_domain_id: pd!.id };
    expect(await defaultRandomAliasDomain(env.DB, withPub, testEnv, NOW)).toBe(
      "first.test",
    );
  });
});

describe("query helpers", () => {
  it("aliasMailboxIds returns primary first then extras; userVerifiedMailboxes is verified+sorted", async () => {
    const user = await createUser(env.DB);
    const mbZ = await createMailbox(env.DB, user.id, "z@mb.test");
    const mbA = await createMailbox(env.DB, user.id, "a@mb.test");
    const unverified = await createMailbox(env.DB, user.id, "unv@mb.test", {
      verified: 0,
    });
    const alias = await createAlias(env.DB, user.id, mbZ.id);
    await env.DB.prepare(
      "INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1,?2)",
    )
      .bind(alias.id, mbA.id)
      .run();

    expect(await aliasMailboxIds(env.DB, alias.id)).toEqual([mbZ.id, mbA.id]);

    const verified = (await userVerifiedMailboxes(env.DB, user.id)).map(
      (m) => m.email,
    );
    // default mailbox is user email; excludes the unverified one; email-sorted
    expect(verified).not.toContain("unv@mb.test");
    expect(verified).toEqual([...verified].sort());
    expect(verified).toContain("a@mb.test");
    expect(unverified.verified).toBe(0);
  });
});
