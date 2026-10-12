#!/usr/bin/env bash
export PATH="$HOME/.cargo/bin:$PATH" CARGO_TARGET_DIR=$HOME/p1_target
cd ~/kappa-registry-p1 && date -u +"start %H:%MZ" && cargo test --release -p kappa-core kappa 2>&1 | grep -v '^ *Compiling\|^ *Downloading\|^ *Downloaded' | grep 'test result\|running\|FAILED\|panicked\|error' | head -20; echo "EXIT=${PIPESTATUS[0]}"; date -u +"done %H:%MZ"
