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

## Qualification baseline: 2026-08-26

The deterministic and live evidence above was produced from this exact source
set:

- runtime API design-freeze baseline: `coppice` at
  `360170369dd2517fd86a7efc5ccc094fed3bb948`;
- Names application qualification code: `coppice-names` at
  `2dc9b8e5702b9fbcf75b5fe27a7948b68ddd55d4`;
- Receipts qualification code: `coppice-receipts` at
  `37b3b17e6223931858296427046622cb6373ca32`;
- reference wallet qualification harness: `zcash-devtool` at
  `b3ce2b4cf4cb17e46073fca313f24575c655bc6b`;
- Names Orchard proof-extension baseline: `orchard-coppice` at
  `9907318813ceb8d66a9f3fa9fe7ea773a53899a4`, based on upstream Orchard
  `ae3511076ec8ecb39ffc02d9cdaf19c441c5b53d`.

Live qualification used local Zakura `f892b9074002a04a678ef2365ec7658795796572`
and Zaino `b819583a1a6663a01cb7681ac5b5fc2a174596a0`. The preserved Phase 7 run
was `/tmp/coppice-live-qualification.aMnVFQ`: common height 54, abandoned
release at height 55, equal-length replacement at height 185, reorg depth 131,
and rebuilt/fresh snapshot SHA-256
`5a98a002c241606d947b26014aab263f6b2fb835aa9704232abfa8ed43e53d5c`.
Phase 6 logs are preserved at `/tmp/coppice-phase6-deep-reorg.kTkjyE`.

The frozen Names v1 evidence remains `V1_BOND_VK_ID`
`a16074cfadabc4c24bf58732389a4f2d574e25c43f169239ec21da852f5f7adc`,
`COPPICE_BOND_K = 11`, and SHA-256
`451bb41f2589ded5805d44ce85d6769122d7dd5d110c4f3f39bd02470460a1a8`
for `test-vectors/coppice_bond_v1.json`. Existing proof bytes and vectors were
compared byte-for-byte and were unchanged. The live harness is Names-focused;
live Names-plus-Receipts composition was intentionally deferred because the
existing wallet host is not a Receipts product. Deterministic multi-application
coverage remains in the Receipts workspace.

## Audit boundaries and invariants

Zcash consensus and fork choice remain external authorities. Coppice Core owns
canonical replay, transport, routing, acquisition, and composition. Applications
own deterministic state and application-specific semantics. Names owns
BondProof, owner authorization, and bond lifecycle rules. `orchard-coppice`
provides only the non-consensus Halo2 implementation support for that Names
proof. Wallet integration owns private keys, coin selection, protection policy,
and publication.

The qualified boundaries include exact rendezvous receiver binding; separate
Carrier and ExtendedEffects acquisition; full-transaction authentication of
compact effects; application isolation; activation gating; atomic block
publication; aligned rewind; validated snapshots; deterministic rebuild; Core
history authentication of the Names bond root; and frozen BondProof verifier
identity. The fork audit against its upstream base found only the dedicated
`CoppiceBondCircuit`, crate-private `SpendAuthorizingKey::to_scalar`, pinned
Halo2/verifier compatibility changes, lockfile metadata, and explanatory
documentation. The normal Orchard Action circuit is upstream-identical, so
the fork does not alter Zcash consensus proof semantics.

Core remains proof-system agnostic; Names owns the application-specific Halo2
BondProof; the fork exists only to expose the implementation support that proof
needs. This is a qualification baseline and pre-audit/pre-release status, not a
Mainnet-readiness or independent-audit claim.

## Status vocabulary

The repository has a production-authoritative code path and frozen protocol
vectors. That means the qualified implementation is the reference path for
development and integration. It does not mean that Coppice is publicly
deployed, audited, or ready for an operational rollout without future network,
packaging, and deployment decisions.
