# PayLink Phase 4 — Analytics & Hardening

## Scope
This phase finalizes the MVP by adding analytics tracking, a merchant dashboard, background cleanup routines, and abuse guardrails.

**In Scope:**
- `GET /links/:code/stats` to view clicks and time-to-pay for a specific link.
- `GET /links` merchant dashboard endpoint.
- Tracking clicks on the redirect endpoint.
- Background job using `setInterval` to expire stale links automatically.
- Custom database-backed rate limit guardrails specifically for the `POST /links` endpoint (max 50 links per hour per user).
- Console warnings for suspiciously high-frequency high-value link creation.
- Architecture and Decision Records written in `docs/`.

## Usage
1. `npm install`
2. `npm start`
3. Hit `GET /links` with your JWT token to see your links.
4. Try creating 51 links in rapid succession to trigger the 429 Too Many Requests guardrail.
