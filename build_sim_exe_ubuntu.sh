#!/usr/bin/env bash
# Cross-compiles demo_attack/sim_intrusion.cpp into a zero-dependency Windows
# 64-bit executable (demo_attack/sim_intrusion.exe) directly from Ubuntu Linux.
set -euo pipefail

OUT="demo_attack/sim_intrusion.exe"

if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
  echo "Using MinGW-w64 (x86_64-w64-mingw32-g++)..."
  x86_64-w64-mingw32-g++ \
    demo_attack/sim_intrusion.cpp \
    -o "$OUT" \
    -O2 -static -static-libgcc -static-libstdc++ -lws2_32
elif command -v zig >/dev/null 2>&1; then
  echo "Using zig c++ (-target x86_64-windows-gnu)..."
  zig c++ -target x86_64-windows-gnu -O2 \
    demo_attack/sim_intrusion.cpp \
    -o "$OUT" \
    -lws2_32
elif [ -x ".venv/bin/python" ] && .venv/bin/python -c "import ziglang" >/dev/null 2>&1; then
  echo "Using .venv ziglang c++ (-target x86_64-windows-gnu)..."
  .venv/bin/python -m ziglang c++ -target x86_64-windows-gnu -O2 \
    demo_attack/sim_intrusion.cpp \
    -o "$OUT" \
    -lws2_32
else
  echo "No Windows cross-compiler found."
  echo "Option 1 (no sudo): .venv/bin/pip install ziglang && ./build_sim_exe_ubuntu.sh"
  echo "Option 2 (apt):     sudo apt update && sudo apt install -y mingw-w64 && ./build_sim_exe_ubuntu.sh"
  exit 1
fi

echo "Built Windows executable: $OUT"
file "$OUT"
ls -lh "$OUT"
