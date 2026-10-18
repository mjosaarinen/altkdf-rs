# Notices

This repository is released as `altkdf-rs`. Original project-authored code and
project-authored documentation are licensed under the BSD 3-Clause License; see
`LICENSE`.

Third-party and standards-derived material is handled separately:

- `rustls-integration/rustls/` is a modified copy of `rustls` 0.23.41. It remains
  under `Apache-2.0 OR ISC OR MIT`; see `rustls-integration/rustls/LICENSE-*`.
- Some tests, constants, labels, tables, TLS presentation syntax, and vector
  material are derived from IETF documents, including RFC 8446, RFC 9861, and
  `draft-sullivan-tls-xof-schedule`. The appendix fixtures are attributed in
  `deck-schedule/vectors/README.md`. For IETF Code Components used here:

  Copyright (c) 2018, 2025, 2026 IETF Trust and the persons identified as
  authors of the code. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, is permitted pursuant to, and subject to the license terms
  contained in, the Revised BSD License set forth in Section 4.c of the IETF
  Trust's Legal Provisions Relating to IETF Documents
  (https://trustee.ietf.org/license-info).

- Known-answer tests and algorithm material from NIST FIPS 202
  are attributed to NIST. NIST publications are public information in the United
  States unless otherwise marked; attribution is requested by NIST.
- Registry dependencies retain their own licenses as declared in their crate
  metadata. Preserve dependency notices when redistributing binaries or vendored
  dependency source.
