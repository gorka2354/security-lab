# pmarket CTFExchange — missing `signer == maker` binding → forged-order fund theft

**Target:** pmarket.ai (Brazilian prediction market; author `github.com/lfpossebon/pmarket-contracts`)
**Contract:** `CTFExchange` at `0x2640Ca9114737f9384B4bc16928f066c92EA3004` — **Polygon mainnet (chain 137)**
**Related:** ConditionalTokens `0x77D04D23Cb06807467E280cfAC46704299478451`, UmaCtfAdapter `0x467eCaebc56f352057b20cfb5eA5957cb629E79d`, FeeModule `0x2F43Be22CB8c6CE3774b3F5c3bF8942b0315f3C6`
**Class:** broken signature authentication — a security-critical binding dropped in a fork of Polymarket's ctf-exchange
**Severity:** High **as a code defect**; **currently Low real-world $** (system dormant, pre-migration — see §Threat).
**Verified:** deployed Etherscan-verified source read directly + Foundry PoC 1/1 (local, no live-contract interaction).

---

## 1. The defect

`CTFExchange.matchOrders` authenticates each order through `_assertOrderWithSig`. On the **deployed** source
(`contracts/src/CTFExchange.sol`, lines 257–258; byte-identical to the repo):

```solidity
function _assertOrderWithSig(Order calldata order, bytes calldata sig) internal view {
    bytes32 orderHash = hashOrder(order);
    ...
    if (order.nonce != nonces[order.maker]) revert InvalidNonce();          // nonce read from order.maker
    if (ECDSA.recover(orderHash, sig) != order.signer) revert InvalidSignature();  // sig checked vs order.signer
}
```

The signature is verified against **`order.signer`**, but the funds are pulled from **`order.maker`**:

```solidity
// matchOrders
_transferAsset(takerOrder.maker, address(this), takerMakerAsset, making);   // line 219 — debits taker.maker
// _fillMakerOrder
_transferAsset(makerOrder.maker, address(this), makerAssetId, making);      // line 326 — debits maker.maker
```

**There is no check anywhere that `order.signer == order.maker`.** `signer` and `maker` are fully decoupled,
and the nonce gate reads `nonces[order.maker]` (the victim's own, untouched nonce). So an attacker can author an
order that debits **any** account while signing it with **their own** key.

### Why this is a drift from audited upstream
pmarket forks Polymarket's ctf-exchange (the repo's own `README`/`STATUS.md` state the contracts *"derivam de
código auditado"* and that no external audit was performed). Polymarket's reference enforces the binding
precisely because the maker is the debited party — its EOA path (`verifyEOASignature`) requires
`signer == maker`. **This fork removed that invariant.** The one-line guard that upstream relies on for
custody safety is absent here.

## 2. Exploit (self-cross to redirect a victim's funds to the attacker)

Every trader grants the exchange a one-time standing approval (ERC-20 allowance for USDC / ERC-1155
`setApprovalForAll` for outcome tokens) — on-chain today ~200 addresses hold a live USDC allowance and ~222 an
ApprovalForAll. Pick any such victim `V`:

1. **Taker order** `{maker: V, signer: ATTACKER, taker: 0, tokenId: yes, makerAmount: 100e6, takerAmount: 100e6, nonce: 0, feeRateBps: tradeFeeBps, side: BUY}` — signed with the **attacker's** key.
   `_assertOrderWithSig` passes: `recover == ATTACKER == order.signer`; `nonce == nonces[V] == 0`.
2. **Maker order** `{maker: ATTACKER, signer: ATTACKER, tokenId: yes, side: SELL, ...}` — the attacker's own,
   backed by (near-worthless) `yes` tokens + ApprovalForAll.
3. The crossing pair is submitted to pmarket's off-chain order API; the operator relays
   `matchOrders(taker, maker, ...)`.
4. On-chain: `usdc.transferFrom(V, exchange, 100e6)` via V's standing approval → the USDC is paid out to the
   **attacker** (the SELL side); V receives 100e6 worthless `yes`. **V authorized nothing beyond the ordinary
   one-time approval.**

A symmetric variant (attacker as BUY, victim's outcome tokens as the maker asset) drains the CTF holdings of
any `setApprovalForAll` grantor.

## 3. Proof of concept

`PoC_ForgedMaker.t.sol` (in this folder). It deploys the **repo's own** `CTFExchange` + `FeeModule` (byte-identical
to deployed on the vulnerable path), gives `victim` 100e6 USDC + a standing max approval (mirroring the 200 real
approvers), gives `attacker` worthless `yes` + ApprovalForAll, then builds `taker{maker:victim, signer:attacker,
BUY}` and `maker{maker:attacker, signer:attacker, SELL}` — **both signed only with the attacker's key** — and has
the operator call `matchOrders`.

```
forge test --match-path test/PoC_ForgedMaker.t.sol -vv
```
```
[PASS] test_forgedMaker_drains_victim_USDC()
  victim USDC lost    : 100.000000
  attacker USDC gained: 100.000000
  victim junk YES recv: 100.000000
```
Reproduction: copy `PoC_ForgedMaker.t.sol` into `test/` of the `pmarket-contracts` repo (OpenZeppelin +
sources already resolve there) and run the command above. No live-contract interaction — the proof is local
against the team's own unmodified source. (Confirmed independently against the deployed Etherscan-verified
source: same lines 257–258, no binding.)

## 4. Kill-gates

- **(a) Reachability — the one honest caveat.** `matchOrders` is `onlyOperator`, and on-chain **only** the
  operator key `0x6c24…4c1e3` has ever called it (623/623 matchOrders txs). A direct on-chain drain therefore
  needs the **off-chain matcher** to accept and relay the forged crossing pair, and that matcher's source is not
  in the repo. Two cases: **(i)** if the matcher relies on the on-chain contract as the signature authority
  (the normal CLOB design, and what upstream assumes) → **fully exploitable**; **(ii)** if the matcher
  independently re-checks `signer == maker` before relaying → blocked at the API, and the on-chain gap is a
  latent defense-in-depth hole that becomes live the moment any other relayer/path is added. The ~4.5% on-chain
  `matchOrders` revert rate suggests the matcher does **not** fully pre-simulate. Either way the on-chain
  contract — the canonical signature authority in a CLOB — must enforce the binding itself.
- **(b) Neutralizing guard — none.** `_validateTaker` only constrains the `taker` field; no `signer`/`maker`
  binding exists; the nonce uses the victim's own nonce.
- **(c) Is this the deployed code — yes.** Read directly from the Etherscan-verified source at the live address
  (20 files); the two decisive lines are present verbatim.
- **(d) Already known/fixed — no.** README: *"Auditoria externa não realizada."* No public bounty program
  (checked). Deployed code still vulnerable.

## 5. Threat / current impact (honest)

`threat.py`: the deployed exchange is effectively **dormant / pre-launch** — production markets still run on the
Phase-1 off-chain model per `STATUS.md`; last on-chain trade ~135 days ago; **currently ~$40 total drainable**
(~$32 USDC across the 200 approvers + ~$8 CTF collateral). So the **present** real-world loss is small.

**But the disclosure value is high and pre-adoption:** the team's roadmap is to migrate production volume onto
this on-chain layer. The moment that happens, **every** user with a standing approval is drainable up to their
allowance/balance — scaling to full protocol TVL. This is the same profile as our Krystal / Pulso findings:
a real, confirmed defect with low current $ but high value if disclosed **before** adoption. Fixing it now costs
one line.

## 6. Fix

Add the binding to `_assertOrderWithSig` (matching Polymarket's EOA path), before or with the signature check:

```solidity
if (order.signer != order.maker) revert InvalidSignature(); // EOA orders: the signer must be the debited maker
```
(If pmarket intends to support delegated signing / smart-contract wallets, replace this with an explicit,
audited authorization model — an `isApprovedSigner[maker][signer]` map or EIP-1271 — rather than leaving
`signer` unbound. Upstream keeps EOA and 1271 paths separate for exactly this reason.)
