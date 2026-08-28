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
and Zaino `b819583a1a6663a01cb7681ac5b5fc2a174596a0`. The preserved final Phase 7
run was `/tmp/coppice-live-qualification.EAT8lm`: common height 54, abandoned
release at height 55, equal-length replacement at height 185, reorg depth 131,
old/new height-185 tip hashes
`23a48edd76576607b828789d18f7cc023076849bca542765de004ac754ef1868` /
`2cf39a410ab57fb3eedcf7f3f4e9144c025fffc4a728d3b21d8d58bcc082c69f`, and
rebuilt/fresh snapshot SHA-256
`a3c54cd9cf89887faa2c610562bacab7db946da71196111f18b1ab1c05cc6d09`.
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

## Names v2 release qualification: 2026-08-28

The full Names v2 lifecycle was qualified live on a fresh disposable
Zakura -> patched Zaino -> `zcash-devtool` stack through the production
construction layer (`zcash-devtool::names_v2_operation` over the
designated-pair builder), not copied qualification code. The run used the
disposable qualification mnemonic, activation heights 1/2, and the
`live-qualification.sh --phase 9` procedure (extended in this release to drive
the complete lifecycle and the claimability boundary).

Live canonical sequence (all verified by independent full replay and
FreshResolver with `NAMES_FULL_FRESH_MATCH=yes`):

- COMMIT `8f2dcc625f0b60bd30fd1384593b0be9ef8158639bf0be424ebdd72edeec80c9`
  mined at height 15 (maturity distance 8 to its scheduled REVEAL anchor);
- REVEAL `4591bd8bcaccee66f25fa27e41dbefe0ad35038912cfc33733b7936d4bed08a0`
  mined at the scheduled anchor height 23; registration resolved `Active`;
- UPDATE `e73bdd5dffbcf14c2aca928e179f3e3c6d0f48c39d1874096e2e6d100484c9dc`
  mined at height 24 and canonically accepted;
- RENEW `16827d5b754c2d3c3c84ccd5ac029e14fb5177ac705aa3f53c6573243da808b8`
  mined at the next scheduled anchor height 27 and canonically accepted;
- RELEASE `22839d5cf22202ad300b4e2aadf867326c8869c10c1f59f6802a73e7685bb500`
  mined at height 28 and canonically accepted;
- claimability boundary: the terminal release resolved `Released` at the last
  blocked height 31 and `Expired` exactly at the claimability height 32
  (`terminal_height 28 + reuse_delay 4`), with replay and FreshResolver in
  agreement at both boundaries.

Measured live costs: Names genesis/transition proofs 3,667-3,886 ms and
4,640-byte proofs; Ironwood consensus proofs 41,326-44,987 ms per
transaction; CNV2 envelopes 5,054 (REVEAL) and 4,947 (UPDATE/RENEW/RELEASE)
bytes at 11/10/10/10 CPV1 frames respectively.

Frozen release identities recorded by this qualification: the Names v2 wire
vector set `0c9bfdd7b0a26fb5c645b356f418d97fb48c7d910e2d1ce0e8d18c3e7f2cb7d5`
(`test-vectors/names_v2_wire.json`), the state-note circuit verifying-key
identities (transition
`676e9883651309ad75e73ff937d3f046cfe966c18079371f80d3f91ded4baf17`, genesis
`a9cfe4bf4c9ff3abeebb41c348e4189f5ec5649f16296c04f573f3d97de952fc`), and the
pinned stack: `coppice-names` at the release head, `orchard-coppice`
production pin `deea5a3b499c9f4e9e30ff4d9ffca4e0f51234ca` (the fork
repository later advanced to `bf689decb9fce94a7de01b8bdc55a1e42e1695bb` for
documentation and VK-freeze-test additions only), `zcash-devtool` at the
release head, Zakura
`f892b9074002a04a678ef2365ec7658795796572`, Zaino
`b819583a1a6663a01cb7681ac5b5fc2a174596a0`, Zallet
`f904040613d6b2c3f24ab58cfef1b555bf68e918` (external, unmodified).

Explicit-replacement, no-predecessor reset, abandonment, competing-transition
reorg, and FreshResolver/full-replay parity behaviors remain covered by the
previously retained live v2 qualification evidence and the deterministic
regression suites; this release qualification demonstrates the production
construction path end to end rather than regenerating every historical live
transaction.
