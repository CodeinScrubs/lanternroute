# Third-party components

LanternRoute downloads and runs these pinned Windows components at runtime:

- [sing-box 1.13.14](https://github.com/SagerNet/sing-box), downloaded from
  the official GitHub release and verified against the pinned SHA-256 value in
  `src/engine.rs`.
- [Wintun 0.14.1](https://www.wintun.net/), downloaded from the official
  Wintun distribution and verified against the pinned SHA-256 value in
  `src/engine.rs`.

The release ZIP contains the LanternRoute binaries and documentation, not
the runtime downloads. Review the upstream licenses and release terms before
redistributing a modified package.
