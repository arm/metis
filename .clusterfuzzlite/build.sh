#!/bin/bash
set -eux

export PIP_IGNORE_REQUIRES_PYTHON=1
pip3 install --ignore-requires-python .

for fuzzer in $(find "$SRC/tests/fuzzing" -name '*_fuzzer.py'); do
  name=$(basename -s .py "$fuzzer")
  pkg="${name}.pkg"

  pyinstaller --distpath "$OUT" --onefile --name "$pkg" "$fuzzer"

  cat > "$OUT/$name" << 'EOF'
#!/bin/sh
dir=$(dirname "$0")
"$dir/${pkg}" "$@"
EOF
  chmod +x "$OUT/$name"
done
