- We're going to follow the functional core, imperative shell pattern. The core will live in the src/core/ folder.
- We prefer short, testable functions. Each function should have positive and negative tests.
- We prefer early return rather than nested logic.
- Readability of code is of utmost importance.
- Any shortcuts or loose ends left during our work should be documented in TODO.md
- Our project is a wireguard implementation with a central coordination server
(gateway). The coordination server handles registration and the sharing of public
keys and connection details between peers.
- when wireguard peers start they generate diffie hellman keys, then register with the gateway using an auth key. During registration they send their public key, public ip and port, and private ip and port. public ip and port are discovered by external stun server.
- our project is written in zig
- Keep tests in separate files from implementation
- Split code in src/core by responsibility - one file per logical concept.
- Group related types and their operations together. For example:
    - Types and constants in one file
    - Core operations for one type in another file
    - Complex multi-step operations in their own files
- If a file handles more than one major responsibility, split it
- Create subdirectories to group related files. For example, if you have multiple files for one feature (noise_ik), put them in their own folder (src/core/noise_ik/)
- Use standard zig testing practices of a seperate test file per module
- always run make test and make install after a change. make test returns nothing on success.
