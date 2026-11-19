#!/usr/bin/env bash
# P1: build + run the scratch crate as a MEMBER of a WSL-side copy of the vendored kappa-registry clone.
# The copy differs from the clone only by: the removed [[test]] block in the root Cargo.toml (cargo 1.96 rejects it in a
# virtual manifest), the added member p1_check, the workspace dcbor pinned to the clone's locked rev 2e5b901e (branch -> rev)
# and the clone's Cargo.lock removed (cargo 1.96 cannot parse it: inventory listed twice), so other deps resolve fresh.
# The clone on /mnt/c is never edited.
export PATH="$HOME/.cargo/bin:$PATH" CARGO_TARGET_DIR=$HOME/p1_target
date -u +"start %H:%MZ"
rsync -a --delete --exclude target --exclude .git /mnt/c/Users/mitch/kappa-registry-main/ ~/kappa-registry-p1/ && echo "copied clone"
python3 - <<'PY'
import os
p='/home/mitch/kappa-registry-p1/Cargo.toml'; s=open(p).read()
i=s.index('[[test]]'); j=s.index('[profile.release]', i); s=s[:i]+s[j:]
s=s.replace('members = [', 'members = [\n    "p1_check",', 1)
a='dcbor = { git = "https://github.com/usrbinkat/bc-dcbor-rust", branch = "feat/dcbor-derive", features = ["derive", "multithreaded"] }'
b='dcbor = { git = "https://github.com/usrbinkat/bc-dcbor-rust", rev = "2e5b901e8c9946794c5491cf92eeec2540b84261", features = ["derive", "multithreaded"] }'
assert s.count(a)==1; s=s.replace(a,b)
open(p,'w').write(s); os.remove('/home/mitch/kappa-registry-p1/Cargo.lock')
print('copy: [[test]] removed, member p1_check added, dcbor pinned to rev 2e5b901e, Cargo.lock removed')
PY
mkdir -p ~/kappa-registry-p1/p1_check/src
cp /mnt/c/Users/mitch/uor_kappa_mage/kappa_evidence/p1_check/src/main.rs ~/kappa-registry-p1/p1_check/src/
printf '[package]\nname = "p1_check"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[dependencies]\nkappa-core = { path = "../crates/kappa-core" }\ndcbor = { workspace = true }\nhex = { workspace = true }\n' > ~/kappa-registry-p1/p1_check/Cargo.toml
cd ~/kappa-registry-p1 && cargo run --release -p p1_check 2>&1 | grep -v '^ *Compiling\|^ *Downloading\|^ *Downloaded\|^ *Updating\|^ *Locking\|^ *Adding' | tail -40
echo "EXIT=${PIPESTATUS[0]}"; date -u +"done %H:%MZ"
