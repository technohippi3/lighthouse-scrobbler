# Passkey compatibility log

These are results from `enroll-passkey` and `restore`. Since the hosted page
went live, ceremonies run on `lhs-passkey-staging.piratesocialclub.workers.dev`
by default. Earlier rows used the `localhost` prototype. A combination counts
as working only when two things hold: enrollment returned PRF output, and a
restore into an empty profile brought back the same history.

| Date | Browser | OS | Authenticator | Enroll (PRF) | Restore, empty profile | Different computer |
|---|---|---|---|---|---|---|
| 2026-11-07 | Helium (Chromium-based), `localhost` page | Linux Mint, X11 | YubiKey over USB (FIDO2 PIN) | Works | Works: 3 of 3 plays, same backup key | Not yet tested |
| 2026-11-07 | Helium, hosted `workers.dev` page | Linux Mint, X11 | YubiKey over USB (FIDO2 PIN) | Works, using "Use a security key" | Works: 3 of 3 test plays, then 18 of 18 real plays | Not yet tested |

## Still to test

- The same YubiKey on a different computer, restoring from a copy of the
  backup folder. This is the decisive test.
- A second, independent passkey on the same backups, such as a second
  YubiKey or a phone over the QR-code route. Then restore with each one.
- A synced provider for users without a hardware key: Chrome with Google
  Password Manager, a phone over the QR-code route, and Firefox on Linux.
- A provider that lacks PRF. It should fail with a clear message and save
  nothing.

## Notes

- A hosted page cannot reliably call the app on `127.0.0.1`. The built-in
  browser blocked it outright, and Chromium's local-network permission
  prompt, Helium's blocker and Brave can do the same. The page therefore
  drops its sealed result in a same-site mailbox on the Worker, which the app
  long-polls.
- "Your device can't be used with this site" in Chrome turned out to mean
  that the YubiKey's discoverable-credential slots were full. Deleting old
  credentials fixed it. The page's "Use a security key" button also sends the
  WebAuthn `security-key` hint, so the browser offers the USB key instead of
  a built-in authenticator that can't create this passkey.
- Test credentials belong to the domain `localhost` and use a resident slot
  on the YubiKey. Delete them after testing with Yubico Authenticator or
  `ykman fido credentials delete`.
- A hardware key is not synced. Losing it loses access unless a second
  passkey is enrolled, so treat a single YubiKey as one recovery method, not
  two.
