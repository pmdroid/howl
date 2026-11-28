import type { D1Database } from "@cloudflare/workers-types";

declare global {
  interface Env {
    DB: D1Database;
    WEB_ORIGIN: string;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    GITHUB_OWNER_ID?: string;
    CONTROL_AUDIENCE: string;
    CONTROL_STATE_KEY: string;
  }
}
