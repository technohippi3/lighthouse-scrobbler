// Serves the passkey ceremony page and a one-shot mailbox that carries the
// page's result back to the lighthouse-scrobbler app.
//
// Session parameters travel in the URL fragment, which never reaches this
// Worker. The mailbox only ever holds a result already sealed to the app's
// per-session key, so this Worker sees ciphertext and a random mailbox ID.
import { DurableObject } from "cloudflare:workers";
import page from "../../src/ceremony.html?raw";

const PAGE_HEADERS: Record<string, string> = {
	"Content-Type": "text/html; charset=utf-8",
	"Cache-Control": "no-store",
	"Content-Security-Policy": [
		"default-src 'none'",
		"script-src 'unsafe-inline'",
		"style-src 'unsafe-inline'",
		"connect-src 'self'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	].join("; "),
	"Referrer-Policy": "no-referrer",
	"Strict-Transport-Security": "max-age=31536000",
	"X-Content-Type-Options": "nosniff",
	"Cross-Origin-Opener-Policy": "same-origin",
	"Permissions-Policy": "publickey-credentials-create=(self), publickey-credentials-get=(self)",
};
const MAILBOX_ID = /^[A-Za-z0-9_-]{22,64}$/;
const MAX_MESSAGE = 16 * 1024;
const MAILBOX_TTL_MS = 10 * 60 * 1000;
const LONG_POLL_MS = 20 * 1000;

const plain = (status: number, body = "") =>
	new Response(body || null, { status, headers: { "Cache-Control": "no-store" } });

export class Mailbox extends DurableObject {
	private waiters: Array<(message: string | null) => void> = [];

	async fetch(request: Request): Promise<Response> {
		if (request.method === "PUT") {
			const message = await request.text();
			if (message.length === 0 || message.length > MAX_MESSAGE) return plain(413);
			if (await this.ctx.storage.get("message")) return plain(409);
			await this.ctx.storage.put("message", message);
			await this.ctx.storage.setAlarm(Date.now() + MAILBOX_TTL_MS);
			for (const wake of this.waiters.splice(0)) wake(message);
			return plain(204);
		}
		if (request.method === "GET") {
			let message = (await this.ctx.storage.get<string>("message")) ?? null;
			if (message === null) {
				message = await new Promise<string | null>((resolve) => {
					this.waiters.push(resolve);
					setTimeout(() => resolve(null), LONG_POLL_MS);
				});
			}
			if (message === null) return plain(204);
			// One read only: the mailbox is emptied as it is collected.
			await this.ctx.storage.deleteAll();
			await this.ctx.storage.deleteAlarm();
			return new Response(message, {
				status: 200,
				headers: { "Cache-Control": "no-store", "Content-Type": "text/plain" },
			});
		}
		return plain(405);
	}

	async alarm(): Promise<void> {
		await this.ctx.storage.deleteAll();
	}
}

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		if (url.pathname === "/" && (request.method === "GET" || request.method === "HEAD")) {
			return new Response(request.method === "HEAD" ? null : page, { headers: PAGE_HEADERS });
		}
		const m = url.pathname.match(/^\/mailbox\/([^/]+)$/);
		if (m && MAILBOX_ID.test(m[1])) {
			// Only the ceremony page itself may drop a message in.
			if (request.method === "PUT" && request.headers.get("Origin") !== url.origin) {
				return plain(403);
			}
			if (request.method !== "PUT" && request.method !== "GET") return plain(405);
			const ns = ctx.exports.Mailbox;
			return ns.get(ns.idFromName(m[1])).fetch(request);
		}
		return plain(404, "Not found");
	},
} satisfies ExportedHandler;
