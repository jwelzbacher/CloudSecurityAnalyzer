cd /Users/jon/CloudSecurityAnalyzer

# Create a script
cat <<'EOF' > fix_python_lint.sh
#!/usr/bin/env bash
set -euo pipefail

echo "🔧 Fixing Python lint issues with ruff..."

# Go to repo root
cd /Users/jon/CloudSecurityAnalyzer

# Create or reuse a virtualenv
if [ ! -d ".venv" ]; then
  echo "➡️  Creating virtualenv .venv"
  python3 -m venv .venv
fi

# Activate venv
# shellcheck source=/dev/null
source .venv/bin/activate

echo "➡️  Upgrading pip and installing ruff..."
python -m pip install --upgrade pip
python -m pip install ruff

echo "➡️  Running ruff auto-fix..."
ruff check . --fix

echo "➡️  Running ruff again to see remaining issues (if any)..."
ruff check .

echo "✅ Done. Review changes with 'git status' and 'git diff' before committing."
EOF

# Make it executable
chmod +x fix_python_lint.sh
