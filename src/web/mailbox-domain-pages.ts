import { Hono } from "hono";
import type { WebEnv } from "../lib/web/webauth";

export const webMailboxDomainPagesRoutes = new Hono<WebEnv>();

// TODO: implemented by the web-view-group agent per cloudflare/specs/web.
