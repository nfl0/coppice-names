# Coppice qualification

Qualification separates deterministic source/test evidence from live local
stack evidence. It is evidence that the pinned code path behaved as recorded;
it is not an independent audit, a public deployment, or a claim that every
future host integration is safe.

## Deterministic coverage

The workspace covers canonical encodings, hostile-input parsing, CPV1 and CA01
routing, exact receiver binding, BondProof generation and verification,
application routing, block atomicity, snapshots, retained rewind, rebuild
signaling, wallet lock reconstruction, and fresh replay. The fuzz-property
tests feed deterministic arbitrary inputs through operation and indexed-carrier
parsers; rejection is permitted, panics are not.

## Final live qualification: Zakura -> patched Zaino -> zcash-devtool

The final local qualification used Zakura with the pinned Ironwood/regtest
schedule, the patched Zaino fork with the required Ironwood subtree APIs, and
`zcash-devtool` built from the frozen Coppice runtime. The host remained the
canonical Zcash ordering and fork-choice authority throughout.

The phases covered:

1. Ironwood subtree-root serving through Zaino, wallet sync, and an ordinary
   Ironwood receive/spend.
2. Names `COMMIT`/`REVEAL`/`UPDATE`/`RELEASE`, bond spend, restart recovery, and
   a shallow same-height reorg.
3. Independent same-seed wallet recovery from the Coppice activation birthday,
   canonical replay, bond-lock reconstruction, protected ordinary-send
   rejection, and fresh-wallet Break Bond.
4. Same-seed multi-account registration, distinct `WalletAccountId` values,
   account-scoped pending state and locks, restart recovery, and fresh recovery.
5. Adversarial wallet and PCZT spend-path checks under `Enabled` and
   `GuardOnly`, exact-owner Break Bond, `Off`-mode cleanup, and foreign-lock
   preservation.
6. Deterministic retained/deep-reorg and activation-checkpoint rebuild
   qualification, including equivalence with clean replay.
7. The same real Zakura/Zaino stack advanced an abandoned branch 131 blocks
   beyond the configured 121-block rewind horizon, replaced it with an
   equal-length canonical suffix, forced a rebuild, and verified that the
   active/bond-spent Names outcomes and account locks were correct. An
   independently initialized same-seed wallet produced the same runtime
   snapshot and application outcomes.

Phase 7's 131-block depth is a local reorg fixture, not a security margin. The
qualification stack and its parameters are disposable development/regtest
material. There is no announced public Coppice Testnet or Mainnet deployment,
and no independent security audit.

## Status vocabulary

The repository has a production-authoritative code path and frozen protocol
vectors. That means the qualified implementation is the reference path for
development and integration. It does not mean that Coppice is publicly
deployed, audited, or ready for an operational rollout without future network,
packaging, and deployment decisions.
