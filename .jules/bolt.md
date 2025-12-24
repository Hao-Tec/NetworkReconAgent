## 2025-01-20 - Connection Reuse in ServiceVerifier

**Learning:** `requests.get()` creates a new TCP connection for every call, which incurs significant overhead (DNS + TCP Handshake + SSL Handshake) when checking multiple paths on the same host.
**Action:** Always use `requests.Session()` when making multiple requests to the same host/domain to enable Keep-Alive and connection pooling. This is a low-effort, high-impact optimization for network scanning tools.

## 2025-01-20 - ThreadPoolExecutor Instantiation Overhead

**Learning:** Creating a new `ThreadPoolExecutor` for every small task (e.g., scanning a single host) creates significant overhead when scaling to hundreds of tasks. The cost of spinning up threads and managing the pool structure accumulates.
**Action:** Use a single, shared `ThreadPoolExecutor` instance for the lifetime of the application (or a long-lived context) and reuse it for all tasks. This reduced scan time by ~50% in benchmarks (7s -> 3.5s for 500 hosts).
