import { defineConfig, exports } from "cf/config";
import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

// Staging host for the passkey ceremony page. Passkeys are bound to this
// hostname for good, so the shipping version needs a domain we control.
export default defineConfig({
	worker: {
		name: "lhs-passkey-staging",
		compatibilityDate: "2026-11-04",
		entrypoint,
		workersDev: true,
		exports: {
			Mailbox: exports.durableObject({ storage: "sqlite" }),
		},
	},
});
