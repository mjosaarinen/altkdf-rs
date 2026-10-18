# Notices

`deck-schedule` is the publishable core crate from the `altkdf-rs` repository.
Original crate code is licensed under the BSD 3-Clause License; see `LICENSE`.

Standards-derived material is handled separately:

- Some tests, constants, labels, tables, TLS presentation syntax, and vector
  material are derived from IETF documents, including RFC 8446, RFC 9861, and
  `draft-sullivan-tls-xof-schedule`. Appendix fixtures and their source revision
  are identified in `vectors/README.md`. For IETF Code Components used here:

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

The crate's normal dependency set is `zeroize`; it retains its own license as
declared in crate metadata.
