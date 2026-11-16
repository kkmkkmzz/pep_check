"""Paired comparisons of Sect. 10.5: exact McNemar p-value and Newcombe (1998, method 10) interval
for the difference of paired proportions, from the pooled S0 counts in results_v2/e2_containment_v2.json."""
import json, math


def wilson(x, n, z=1.959964):
    p = x / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def newcombe_paired(a, b, c, d, z=1.959964):
    """a: both fail, b: only first fails, c: only second fails, d: neither. Difference p2 - p1."""
    n = a + b + c + d
    p1, p2 = (a + b) / n, (a + c) / n
    l1, u1 = wilson(a + b, n, z); l2, u2 = wilson(a + c, n, z)
    num = (a * d - b * c)
    den = math.sqrt((a + b) * (c + d) * (a + c) * (b + d))
    phi = 0.0 if den == 0 else num / den
    if num > 0:
        phi = max(0.0, num - n / 2) / den
    diff = p2 - p1
    dl = math.sqrt((p2 - l2) ** 2 - 2 * phi * (p2 - l2) * (u1 - p1) + (u1 - p1) ** 2)
    du = math.sqrt((u2 - p2) ** 2 - 2 * phi * (u2 - p2) * (p1 - l1) + (p1 - l1) ** 2)
    return diff, diff - dl, diff + du


def main():
    d = json.load(open("results_v2/e2_containment_v2.json"))
    pooled = d["S0_pooled"]; mc = d["mcnemar_S0_pooled"]
    n = 10000
    for pair, (b, c, p) in mc.items():
        x, y = [s.strip() for s in pair.split("vs")]
        kx, ky = pooled[x]["false_effective_k"], pooled[y]["false_effective_k"]
        both = kx - b
        assert ky - c == both, pair
        diff, lo, hi = newcombe_paired(both, b, c, n - both - b - c)
        log2p = (1 - (b + c)) if (b == 0 and b + c > 0) else None
        print("%-45s only-first %d, only-second %d, McNemar p = %s; difference %.2f pp [%.2f, %.2f]"
              % (pair, b, c, ("2^%d" % log2p) if log2p is not None else p, 100 * diff, 100 * lo, 100 * hi))


if __name__ == "__main__":
    main()
