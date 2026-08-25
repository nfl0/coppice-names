# Coppice Names v1

Coppice Names v1 is the first application hosted by Coppice Core. This document
explains the user and wallet model; the exact byte encodings, hashes, proof
inputs, and transition order remain exclusively specified by
[`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md) and [`test-vectors/`](../test-vectors/).

## Names and presentation

Names v1 stores a canonical bare label such as `alice`. Names are lowercase
ASCII labels under the protocol's length and hyphen rules. A wallet may accept
or display `alice.zec`, but `.zec` is a presentation suffix: it is removed at
the wallet boundary and never enters the canonical name, commitment, owner
authorization message, state root, or carrier bytes. No case folding or Unicode
normalization is implied.

Names v1 is identified for routing by its `ApplicationId + application_version`.
Its application-specific cryptographic domains and state use
`NamesDeploymentId`. Neither identity is `CoreRuntimeId`.

## Registration

Registration is intentionally two-stage:

1. `COMMIT` publishes a commitment to the desired name, owner authority, bond
   identity, destination, and fresh secret without revealing the name.
2. After the commitment is mature and still within its lifetime, `REVEAL`
   publishes those values and supplies a BondProof tied to an authenticated
   Ironwood anchor. A valid reveal creates the initial active record and removes
   the pending commitment.

A registration bond is an Ironwood note whose nullifier determines the
`bond_tag` used by Names. The bond value, freshness, anchor, proof, and timing
rules are deployment and protocol parameters, not wallet guesses. A rejected
reveal leaves its pending commitment until the specified expiry; a successful
reveal consumes it.

## Bonds and owner authority

An active record contains an owner public key, bond tag, sequence, and canonical
destination. The bond is part of the protocol's anti-reuse and liveness model.
When the canonical chain spends that bond, Core supplies the nullifier to Names;
Names changes the record to terminal `BondSpent` state before interpreting a
later routed Names message in the same transaction.

`UPDATE` changes the destination and increments the sequence. `RELEASE`
terminates the name without transferring ownership. Both require authorization
by the current owner key and the exact next sequence. There is no transfer,
rebond, renewal, or administrative Names operation.

“Break Bond” is a wallet-side workflow for explicitly spending the owned bond
note. It is not a fifth Names protocol operation. The wallet must resolve the
canonical active bond, use the correct owner/account-scoped lock, and satisfy
the host's exact canonical tip checks.

## Reuse and resolution

An active name resolves to its destination and is payable. A released or
bond-spent name is terminal but not immediately reusable: it passes through the
deployment's reuse delay. During that interval it is cooling down; after the
delay it is available for a future valid registration, but it has no payment
destination. Only `Active` is payable.

The application maintains canonical Names records, pending commitments,
recent-spent information, the Names state root, and bounded Names undo history.
These are application state. Core owns the canonical Zcash/Ironwood context and
does not become a Names registry.

## Visibility and limits

Carrier outputs are intentionally decryptable with the configured public
incoming capability, and Names payloads become public protocol data once their
transaction is visible. Commit/reveal hides the preimage only until reveal;
Names v1 does not claim long-term privacy for names or destinations.

The repository's Testnet and Regtest values are qualification/development
parameters. There is no announced public Coppice Testnet or Mainnet deployment,
and no independent security audit.
