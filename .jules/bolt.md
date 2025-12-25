## 2025-01-20 - Connection Reuse in ServiceVerifier

**Learning:** `requests.get()` creates a new TCP connection for every call, which incurs significant overhead (DNS + TCP Handshake + SSL Handshake) when checking multiple paths on the same host.
**Action:** Always use `requests.Session()` when making multiple requests to the same host/domain to enable Keep-Alive and connection pooling. This is a low-effort, high-impact optimization for network scanning tools.

## 2025-01-21 - Thread Pool Reuse in PortScanner

**Learning:** Creating a new `ThreadPoolExecutor` for every host scanned (inside `PortScanner`) adds measurable overhead when scanning many hosts, even if the number of ports is small. The overhead comes from thread creation/destruction and context switching.
**Action:** Use a shared `ThreadPoolExecutor` instance in classes that are instantiated once but perform many parallel tasks. Ensure proper lifecycle management (`shutdown`, `__enter__`, `__exit__`) to prevent resource leaks.
