# Privacy Guard

Audience-aware privacy for DSH agents.

- Private facts stay private: `tools/pre-execute` checks outbound calls using the audience inferred from `group_id` / `peer_id` / `comment`. Private DMs are owner-only by default; a non-owner private recipient is blocked just like a group.
- Six tools: `privacy_status`, `privacy_scan`, `privacy_remember`, `privacy_recall`, `privacy_forget`, `privacy_audit`.
- Encrypted scoped vault (AES-256-GCM) with `private` / `group` / `public` labels.
- Hash-chain audit with categories, never message text.

Built for multi-channel agents (QQ groups, Bilibili comments, email) where a private-chat memory can otherwise be recalled into a public reply.

See `README.md` and `docs/威胁模型.md` for the full threat model.
