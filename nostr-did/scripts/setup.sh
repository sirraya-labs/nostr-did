#!/usr/bin/env bash
set -euo pipefail

# ────────────────────────────────────────────────────────────
# nostr-did-key — Project Setup Script
# Generates license files, updates Cargo.toml metadata,
# and prepares the repository for publication.
# ────────────────────────────────────────────────────────────

# ─── Configuration ─────────────────────────────────────────
# Change these values for your project

ORG_NAME="sirraya-labs"
PROJECT_NAME="nostr-did-key"
REPO_URL="https://github.com/${ORG_NAME}/${PROJECT_NAME}"
YEAR=$(date +%Y)
AUTHOR="${ORG_NAME}"

CRATE_DESCRIPTION="Minimal BIP-340 x-only public key to W3C Multikey transformation for did:nostr, with optional secp256k1 validation"
CRATE_KEYWORDS="nostr,did,multikey,ssi,w3c"
CRATE_CATEGORIES="cryptography,no-std,web-programming"

# ─── Colors ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; }

# ─── Pre-flight checks ──────────────────────────────────────
if ! command -v git &> /dev/null; then
    error "git is not installed. Please install git first."
    exit 1
fi

if ! git rev-parse --git-dir &> /dev/null 2>&1; then
    error "Not inside a git repository. Run 'git init' first."
    exit 1
fi

PROJECT_ROOT=$(git rev-parse --show-toplevel)
cd "$PROJECT_ROOT"

info "Project root: ${PROJECT_ROOT}"
info "Organization: ${ORG_NAME}"
info "Project:      ${PROJECT_NAME}"
info "Year:         ${YEAR}"
echo ""

# ────────────────────────────────────────────────────────────
# 1. Generate LICENSE-MIT
# ────────────────────────────────────────────────────────────
info "Generating LICENSE-MIT..."

cat > LICENSE-MIT << 'HEREDOC'
MIT License

Copyright (c) __YEAR__ __AUTHOR__

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
HEREDOC

# Replace placeholders
sed -i "s/__YEAR__/${YEAR}/g" LICENSE-MIT
sed -i "s/__AUTHOR__/${AUTHOR}/g" LICENSE-MIT

success "LICENSE-MIT generated"
echo ""

# ────────────────────────────────────────────────────────────
# 2. Generate LICENSE-APACHE
# ────────────────────────────────────────────────────────────
info "Generating LICENSE-APACHE..."

cat > LICENSE-APACHE << 'HEREDOC'
                              Apache License
                        Version 2.0, January 2004
                     http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

   "License" shall mean the terms and conditions for use, reproduction,
   and distribution as defined by Sections 1 through 9 of this document.

   "Licensor" shall mean the copyright owner or entity authorized by
   the copyright owner that is granting the License.

   "Legal Entity" shall mean the union of the acting entity and all
   other entities that control, are controlled by, or are under common
   control with that entity. For the purposes of this definition,
   "control" means (i) the power, direct or indirect, to cause the
   direction or management of such entity, whether by contract or
   otherwise, or (ii) ownership of fifty percent (50%) or more of the
   outstanding shares, or (iii) beneficial ownership of such entity.

   "You" (or "Your") shall mean an individual or Legal Entity
   exercising permissions granted by this License.

   "Source" form shall mean the preferred form for making modifications,
   including but not limited to software source code, documentation
   source, and configuration files.

   "Object" form shall mean any form resulting from mechanical
   transformation or translation of a Source form, including but
   not limited to compiled object code, generated documentation,
   and conversions to other media types.

   "Work" shall mean the work of authorship, whether in Source or
   Object form, made available under the License, as indicated by a
   copyright notice that is included in or attached to the work
   (an example is provided in the Appendix below).

   "Derivative Works" shall mean any work, whether in Source or Object
   form, that is based on (or derived from) the Work and for which the
   editorial revisions, annotations, elaborations, or other modifications
   represent, as a whole, an original work of authorship. For the purposes
   of this License, Derivative Works shall not include works that remain
   separable from, or merely link (or bind by name) to the interfaces of,
   the Work and Derivative Works thereof.

   "Contribution" shall mean any work of authorship, including
   the original version of the Work and any modifications or additions
   to that Work or Derivative Works thereof, that is intentionally
   submitted to Licensor for inclusion in the Work by the copyright owner
   or by an individual or Legal Entity authorized to submit on behalf of
   the copyright owner. For the purposes of this definition, "submitted"
   means any form of electronic, verbal, or written communication sent
   to the Licensor or its representatives, including but not limited to
   communication on electronic mailing lists, source code control systems,
   and issue tracking systems that are managed by, or on behalf of, the
   Licensor for the purpose of discussing and improving the Work, but
   excluding communication that is conspicuously marked or otherwise
   designated in writing by the copyright owner as "Not a Contribution."

   "Contributor" shall mean Licensor and any individual or Legal Entity
   on behalf of whom a Contribution has been received by Licensor and
   subsequently incorporated within the Work.

2. Grant of Copyright License. Subject to the terms and conditions of
   this License, each Contributor hereby grants to You a perpetual,
   worldwide, non-exclusive, no-charge, royalty-free, irrevocable
   copyright license to reproduce, prepare Derivative Works of,
   publicly display, publicly perform, sublicense, and distribute the
   Work and such Derivative Works in Source or Object form.

3. Grant of Patent License. Subject to the terms and conditions of
   this License, each Contributor hereby grants to You a perpetual,
   worldwide, non-exclusive, no-charge, royalty-free, irrevocable
   (except as stated in this section) patent license to make, have made,
   use, offer to sell, sell, import, and otherwise transfer the Work,
   where such license applies only to those patent claims licensable
   by such Contributor that are necessarily infringed by their
   Contribution(s) alone or by combination of their Contribution(s)
   with the Work to which such Contribution(s) was submitted. If You
   institute patent litigation against any entity (including a
   cross-claim or counterclaim in a lawsuit) alleging that the Work
   or a Contribution incorporated within the Work constitutes direct
   or contributory patent infringement, then any patent licenses
   granted to You under this License for that Work shall terminate
   as of the date such litigation is filed.

4. Redistribution. You may reproduce and distribute copies of the
   Work or Derivative Works thereof in any medium, with or without
   modifications, and in Source or Object form, provided that You
   meet the following conditions:

   (a) You must give any other recipients of the Work or
       Derivative Works a copy of this License; and

   (b) You must cause any modified files to carry prominent notices
       stating that You changed the files; and

   (c) You must retain, in the Source form of any Derivative Works
       that You distribute, all copyright, patent, trademark, and
       attribution notices from the Source form of the Work,
       excluding those notices that do not pertain to any part of
       the Derivative Works; and

   (d) If the Work includes a "NOTICE" text file as part of its
       distribution, then any Derivative Works that You distribute must
       include a readable copy of the attribution notices contained
       within such NOTICE file, excluding those notices that do not
       pertain to any part of the Derivative Works, in at least one
       of the following places: within a NOTICE text file distributed
       as part of the Derivative Works; within the Source form or
       documentation, if provided along with the Derivative Works; or,
       within a display generated by the Derivative Works, if and
       wherever such third-party notices normally appear. The contents
       of the NOTICE file are for informational purposes only and
       do not modify the License. You may add Your own attribution
       notices within Derivative Works that You distribute, alongside
       or as an addendum to the NOTICE text from the Work, provided
       that such additional attribution notices cannot be construed
       as modifying the License.

   You may add Your own copyright statement to Your modifications and
   may provide additional or different license terms and conditions
   for use, reproduction, or distribution of Your modifications, or
   for any such Derivative Works as a whole, provided Your use,
   reproduction, and distribution of the Work otherwise complies with
   the conditions stated in this License.

5. Submission of Contributions. Unless You explicitly state otherwise,
   any Contribution intentionally submitted for inclusion in the Work
   by You to the Licensor shall be under the terms and conditions of
   this License, without any additional terms or conditions.
   Notwithstanding the above, nothing herein shall supersede or modify
   the terms of any separate license agreement you may have executed
   with Licensor regarding such Contributions.

6. Trademarks. This License does not grant permission to use the trade
   names, trademarks, service marks, or product names of the Licensor,
   except as required for reasonable and customary use in describing the
   origin of the Work and reproducing the content of the NOTICE file.

7. Disclaimer of Warranty. Unless required by applicable law or
   agreed to in writing, Licensor provides the Work (and each
   Contributor provides its Contributions) on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied, including, without limitation, any warranties or conditions
   of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
   PARTICULAR PURPOSE. You are solely responsible for determining the
   appropriateness of using or redistributing the Work and assume any
   risks associated with Your exercise of permissions under this License.

8. Limitation of Liability. In no event and under no legal theory,
   whether in tort (including negligence), contract, or otherwise,
   unless required by applicable law (such as deliberate and grossly
   negligent acts) or agreed to in writing, shall any Contributor be
   liable to You for damages, including any direct, indirect, special,
   incidental, or consequential damages of any character arising as a
   result of this License or out of the use or inability to use the
   Work (including but not limited to damages for loss of goodwill,
   work stoppage, computer failure or malfunction, or any and all
   other commercial damages or losses), even if such Contributor
   has been advised of the possibility of such damages.

9. Accepting Warranty or Additional Liability. While redistributing
   the Work or Derivative Works thereof, You may choose to offer,
   and charge a fee for, acceptance of support, warranty, indemnity,
   or other liability obligations and/or rights consistent with this
   License. However, in accepting such obligations, You may act only
   on Your own behalf and on Your sole responsibility, not on behalf
   of any other Contributor, and only if You agree to indemnify,
   defend, and hold each Contributor harmless for any liability
   incurred by, or claims asserted against, such Contributor by reason
   of your accepting any such warranty or additional liability.

END OF TERMS AND CONDITIONS

APPENDIX: How to apply the Apache License to your work.

   To apply the Apache License to your work, attach the following
   boilerplate notice, with the fields enclosed by brackets "[]"
   replaced with your own identifying information. (Don't include
   the brackets!) The text should be enclosed in the appropriate
   comment syntax for the file format. We also recommend that a
   file or class name and description of purpose be included on the
   same "printed page" as the copyright notice for easier
   identification within third-party archives.

Copyright __YEAR__ __AUTHOR__

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
HEREDOC

# Replace placeholders
sed -i "s/__YEAR__/${YEAR}/g" LICENSE-APACHE
sed -i "s/__AUTHOR__/${AUTHOR}/g" LICENSE-APACHE

success "LICENSE-APACHE generated"
echo ""

# ────────────────────────────────────────────────────────────
# 3. Generate .gitignore (Rust best practices)
# ────────────────────────────────────────────────────────────
info "Generating .gitignore..."

cat > .gitignore << 'HEREDOC'
# ── Rust ──────────────────────────────────────────────────────
/target/
**/*.rs.bk
*.pdb

# ── IDE ───────────────────────────────────────────────────────
.idea/
.vscode/
*.swp
*.swo
*~

# ── OS ────────────────────────────────────────────────────────
.DS_Store
Thumbs.db

# ── Environment ───────────────────────────────────────────────
.env
.env.local
HEREDOC

success ".gitignore generated"
echo ""

# ────────────────────────────────────────────────────────────
# 4. Generate .github/workflows/ci.yml
# ────────────────────────────────────────────────────────────
info "Generating GitHub Actions CI workflow..."

mkdir -p .github/workflows

cat > .github/workflows/ci.yml << 'HEREDOC'
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    name: Test (Rust ${{ matrix.rust }})
    runs-on: ubuntu-latest
    strategy:
      matrix:
        rust: [stable, beta]

    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}

      - uses: Swatinem/rust-cache@v2

      - name: Run tests (default features)
        run: cargo test --verbose

      - name: Run tests (all features)
        run: cargo test --verbose --all-features

      - name: Run tests (no_std)
        run: cargo test --verbose --no-default-features

  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt

      - uses: Swatinem/rust-cache@v2

      - name: Check formatting
        run: cargo fmt --all --check

      - name: Run clippy
        run: cargo clippy --all-targets --all-features -- -D warnings

  docs:
    name: Docs
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - uses: Swatinem/rust-cache@v2

      - name: Build documentation
        run: cargo doc --no-deps --all-features
        env:
          RUSTDOCFLAGS: "-D warnings"
HEREDOC

success ".github/workflows/ci.yml generated"
echo ""

# ────────────────────────────────────────────────────────────
# 5. Update Cargo.toml metadata
# ────────────────────────────────────────────────────────────
info "Verifying Cargo.toml metadata..."

if ! grep -q "repository = \"${REPO_URL}\"" Cargo.toml 2>/dev/null; then
    warn "Cargo.toml repository URL may need updating to: ${REPO_URL}"
    warn "Please update manually if needed."
fi

if ! grep -q 'license = "MIT OR Apache-2.0"' Cargo.toml 2>/dev/null; then
    warn "Cargo.toml license field may need updating."
fi

echo ""

# ────────────────────────────────────────────────────────────
# 6. Summary
# ────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════"
echo "  Setup Complete"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Files generated:"
echo "  ✓ LICENSE-MIT"
echo "  ✓ LICENSE-APACHE"
echo "  ✓ .gitignore"
echo "  ✓ .github/workflows/ci.yml"
echo ""
echo "Next steps:"
echo "  1. Review generated files"
echo "  2. Update Cargo.toml if warnings appeared above"
echo "  3. Run: cargo test --all-features"
echo "  4. Run: cargo fmt --all --check"
echo "  5. Run: cargo clippy --all-targets --all-features"
echo "  6. Commit and push"
echo "  7. Run: cargo publish"
echo ""
echo "Repository: ${REPO_URL}"
echo "═══════════════════════════════════════════════════════════"