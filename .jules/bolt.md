## 2025-01-20 - Cache Key Granularity and Object Creation

**Learning:** `functools.lru_cache` is ineffective if the cache key is too specific (e.g., full MAC address instead of OUI prefix), leading to frequent misses and redundant computation. Additionally, defining large constant dictionaries inside a function body causes them to be recreated on every execution (cache miss), adding significant overhead.
**Action:** Move constant data structures to module level. Ensure cache keys are normalized or truncated to the minimum specificity required for the lookup (e.g., use OUI prefix instead of full MAC).
