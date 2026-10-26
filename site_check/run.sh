#!/usr/bin/env bash
# site_check: re-derive every address on agentprivacy.org from the sealed soul_mage bundles with kappa-core itself.
# Runs as a member crate of the WSL-side copy ~/kappa-registry-p1 (see p1_run.sh for how that copy differs from the
# vendored clone; the clone is never edited). The site address list and anchors file are written by the soul_mage
# session (kappa/_site_addresses.txt, kappa/_site_anchors.txt — kappa/ is gitignored there).
export PATH="$HOME/.cargo/bin:$PATH" CARGO_TARGET_DIR=$HOME/p1_target
KE=/mnt/c/Users/mitch/kappa_evidence_mage
rm -rf ~/kappa-registry-p1/site_check && cp -r $KE/site_check ~/kappa-registry-p1/site_check
grep -q '"site_check"' ~/kappa-registry-p1/Cargo.toml || sed -i 's/members = \[/members = [\n    "site_check",/' ~/kappa-registry-p1/Cargo.toml
(cd ~/kappa-registry-p1 && cargo build --release -p site_check 2>&1 | grep -E "^error|Finished")
cd /mnt/c/Users/mitch/soul_mage/kappa && ~/p1_target/release/site_check \
  --site _site_addresses.txt --anchors _site_anchors.txt --text-file $KE/site_check/proverb_sentence.txt \
  fleet-chain work-chain fund-chain research-chain $KE/out/r32 $KE/out/sig_h2_b96b3ca \
  $(ls -d fleet-chain-epochs/*/ 2>/dev/null)
# sealed epochs (2026-10-25): soul_mage chain.py seals each superseded fleet-chain bundle under
# kappa/fleet-chain-epochs/, so an address a page showed under an earlier mint still resolves
