# Names v2 qualification record

This record covers the corrected Names v2 implementation at the pinned
release heads. The live run is local evidence only; it is not a public-network
deployment or an independent security audit.

The qualification path is `zcash-devtool/scripts/live-qualification.sh
--phase 2`. It drives the pinned Zakura -> Zaino -> `zcash-devtool` stack and
checks canonical `COMMIT -> REVEAL -> UPDATE -> RENEW -> RELEASE` acceptance.
Each operation is independently checked by full replay and `FreshResolver`.
The run also checks the exact `Released`/`Expired` claimability boundary.

Frozen artifacts:

- CNV2 revision: `0x02`
- wire-vector identity:
  `0379bf3bf665d3d0ce3a8c9b3a82bf6b67c01a33dc11a26b1b44bd1cd013a556`
- state-note transition VK identity:
  `5ed1a1385f15e0e13e284cf1a7c319449d42b4902abc57b5ebefb60d04995cc1`
- state-note genesis VK identity:
  `81aa1ade09b0ca86eb80c021a66e2cf629875ecab258a99a4a2ecd0df2c7f5ae`
- Orchard source pin: `84e22d5bc62bb138bce5d8a21ec61d3afe01bc12`

Proof-size and performance optimization remain separate post-qualification
work. Final wire/VK regeneration and live qualification must be rerun if any
normative circuit, wire, or protocol-version input changes.
