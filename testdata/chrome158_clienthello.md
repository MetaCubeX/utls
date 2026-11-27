# Chrome 158 ClientHello

The fixture is the first TLS record sent by Chrome for Testing Stable 158.0.8127.88 for Windows x64 to `https://capture.test`. The browser ran headless with a fresh user-data directory, a loopback host resolver rule and no proxy. Three independently launched profiles offered the same ordered capabilities and extension bodies after normalization. The TLS record contains only the public ClientHello.

The regression test compares the entire ClientHello, allowing fresh randomness, GREASE values, ephemeral keys, GREASE ECH payload sizes, and shuffled extension order. A fresh connection from installed Google Chrome 158.0.8127.37 on the same host matched the other capabilities but omitted the experimental server padding request (0x12e0). Trust anchor IDs are a snapshot of the browser's root store.

Select `HelloChrome_158` explicitly. This fork advertises the browser's ML-DSA scheme IDs in this profile and verifies conventional certificate signatures. If a server selects ML-DSA for CertificateVerify the handshake fails. The profile does not install Chrome's trust roots.

[Chrome for Testing build](https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json) · [Upstream Chrome 155 implementation](https://github.com/refraction-networking/utls/commit/6ebdceb2607e8c72942805af16ed4b8f052ee509)
