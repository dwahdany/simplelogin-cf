import { Hono } from "hono";
import type { AppEnv } from "../lib/auth";

export const userRoutes = new Hono<AppEnv>();

// TODO: implemented by the route-group agent per cloudflare/specs.
