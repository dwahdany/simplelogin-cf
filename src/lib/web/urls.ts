/**
 * Flask `url_for` equivalent. The endpoint map is the COMPLETE inventory
 * from specs/web/00-web-infra.md §1.1 — including endpoints of blueprints
 * that are out of port scope (their links must keep pointing at the right,
 * unported URLs) and `discover.index`, which is referenced from inside an
 * HTML comment that Jinja still evaluates (menu.html:38).
 *
 * Unknown endpoint => throw, so a missing entry fails tests loudly instead
 * of emitting a broken href.
 */

/** endpoint -> path template using Flask converter syntax for params */
const ENDPOINTS: Record<string, string> = {
  // in scope: infra (specs/web/00 §3)
  index: "/",
  "auth.login": "/auth/login",
  "auth.logout": "/auth/logout",
  "auth.register": "/auth/register",
  "auth.activate": "/auth/activate",
  "auth.resend_activation": "/auth/resend_activation",
  "auth.forgot_password": "/auth/forgot_password",
  "auth.reset_password": "/auth/reset_password",
  "auth.change_email": "/auth/change_email",
  "auth.mfa": "/auth/mfa",
  "auth.recovery_route": "/auth/recovery",
  "auth.fido": "/auth/fido",
  "auth.social": "/auth/social",
  "auth.api_to_cookie": "/auth/api_to_cookie",
  "auth.github_login": "/auth/github/login",
  "auth.google_login": "/auth/google/login",
  "auth.facebook_login": "/auth/facebook/login",
  "auth.proton_login": "/auth/proton/login",
  "auth.oidc_login": "/auth/oidc/login",
  // in scope: dashboard
  "dashboard.index": "/dashboard/",
  "dashboard.custom_alias": "/dashboard/custom_alias",
  "dashboard.alias_log": "/dashboard/alias_log/<alias_id>",
  "dashboard.alias_export_route": "/dashboard/alias_export",
  "dashboard.alias_transfer_send_route":
    "/dashboard/alias_transfer/send/<alias_id>",
  "dashboard.alias_transfer_receive_route": "/dashboard/alias_transfer/receive",
  "dashboard.alias_contact_manager":
    "/dashboard/alias_contact_manager/<alias_id>",
  "dashboard.contact_detail_route": "/dashboard/contact/<contact_id>",
  "dashboard.toggle_contact": "/dashboard/contacts/<contact_id>/toggle",
  "dashboard.mailbox_route": "/dashboard/mailbox",
  "dashboard.mailbox_detail_route": "/dashboard/mailbox/<mailbox_id>",
  "dashboard.mailbox_verify": "/dashboard/mailbox_verify",
  "dashboard.custom_domain": "/dashboard/custom_domain",
  "dashboard.domain_detail": "/dashboard/domains/<custom_domain_id>/info",
  "dashboard.domain_detail_dns": "/dashboard/domains/<custom_domain_id>/dns",
  "dashboard.domain_detail_trash":
    "/dashboard/domains/<custom_domain_id>/trash",
  "dashboard.domain_detail_auto_create":
    "/dashboard/domains/<custom_domain_id>/auto-create",
  "dashboard.subdomain_route": "/dashboard/subdomain",
  "dashboard.directory": "/dashboard/directory",
  "dashboard.batch_import_route": "/dashboard/batch_import",
  "dashboard.refused_email_route": "/dashboard/refused_email",
  "dashboard.setting": "/dashboard/setting",
  "dashboard.account_setting": "/dashboard/account_setting",
  "dashboard.resend_email_change": "/dashboard/resend_email_change",
  "dashboard.cancel_email_change": "/dashboard/cancel_email_change",
  "dashboard.unlink_proton_account": "/dashboard/unlink_proton_account",
  "dashboard.api_key": "/dashboard/api_key",
  "dashboard.enter_sudo": "/dashboard/enter_sudo",
  "dashboard.mfa_setup": "/dashboard/mfa_setup",
  "dashboard.mfa_cancel": "/dashboard/mfa_cancel",
  "dashboard.fido_setup": "/dashboard/fido_setup",
  "dashboard.fido_manage": "/dashboard/fido_manage",
  "dashboard.delete_account": "/dashboard/delete_account",
  "dashboard.notifications_route": "/dashboard/notifications",
  "dashboard.notification_route": "/dashboard/notification/<notification_id>",
  "dashboard.unsubscribe": "/dashboard/unsubscribe/<alias_id>",
  "dashboard.block_contact": "/dashboard/block_contact/<contact_id>",
  "dashboard.encoded_unsubscribe":
    "/dashboard/unsubscribe/encoded/<encoded_request>",
  "dashboard.billing": "/dashboard/billing",
  "dashboard.pricing": "/dashboard/pricing",
  "dashboard.subscription_success": "/dashboard/subscription_success",
  "dashboard.coupon_route": "/dashboard/coupon",
  "dashboard.lifetime_licence": "/dashboard/lifetime-licence",
  "dashboard.referral_route": "/dashboard/referral",
  "dashboard.support_route": "/dashboard/support",
  "dashboard.app_route": "/dashboard/app",
  "dashboard.setup_done": "/dashboard/setup_done",
  "dashboard.enter_admin": "/dashboard/enter_admin",
  // out of scope, links must stay correct (00-web-infra §1.1)
  "phone.index": "/phone/",
  "phone.reservation_route": "/phone/reservation/<reservation_id>",
  "developer.index": "/developer/",
  "developer.new_client": "/developer/new_client",
  "developer.client_detail": "/developer/clients/<client_id>",
  "developer.client_detail_oauth_setting":
    "/developer/clients/<client_id>/oauth_setting",
  "developer.client_detail_oauth_endpoint":
    "/developer/clients/<client_id>/oauth_endpoint",
  "developer.client_detail_advanced": "/developer/clients/<client_id>/advanced",
  "developer.client_detail_referral": "/developer/clients/<client_id>/referral",
  "discover.index": "/discover/",
  "onboarding.index": "/onboarding/",
  "onboarding.setup": "/onboarding/setup",
  "onboarding.setup_done": "/onboarding/setup_done",
  "onboarding.final": "/onboarding/final",
  "onboarding.account_activated": "/onboarding/account_activated",
  "onboarding.extension_redirect": "/onboarding/extension_redirect",
  "oauth.authorize": "/oauth/authorize",
  "oauth.token": "/oauth/token",
  "oauth.user_info": "/oauth/user_info",
  "internal.exit_sudo_mode": "/internal/exit-sudo-mode",
  "internal.set_enable_proton_cookie": "/internal/integrations/proton",
  "monitor.git_sha1": "/git",
  "monitor.version": "/version",
  "monitor.live": "/live",
  "monitor.test_exception": "/exception",
};

/**
 * Build a URL like Flask's url_for: path params substituted, `_anchor`
 * becomes `#fragment`, every other kwarg becomes a query-string pair.
 * `url_for("static", filename="js/an.js", v="2")` -> `/static/js/an.js?v=2`.
 */
export function urlFor(
  endpoint: string,
  params: Record<string, unknown> = {},
): string {
  const rest: Record<string, unknown> = { ...params };
  delete rest.__keywords; // nunjucks kwargs marker
  let anchor = "";
  if ("_anchor" in rest) {
    anchor = `#${rest._anchor}`;
    delete rest._anchor;
  }

  let path: string;
  if (endpoint === "static") {
    path = `/static/${rest.filename}`;
    delete rest.filename;
  } else {
    const template = ENDPOINTS[endpoint];
    if (!template) throw new Error(`urlFor: unknown endpoint "${endpoint}"`);
    path = template.replace(/<(?:[a-z]+:)?([a-zA-Z_]+)>/g, (_, name) => {
      if (!(name in rest))
        throw new Error(`urlFor: missing param "${name}" for "${endpoint}"`);
      const v = String(rest[name]);
      delete rest[name];
      return encodeURIComponent(v);
    });
  }

  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(rest)) {
    if (v !== undefined && v !== null) qs.set(k, String(v));
  }
  const q = qs.toString();
  return path + (q ? `?${q}` : "") + anchor;
}
