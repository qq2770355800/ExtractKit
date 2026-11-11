#!/bin/sh
# 用一次性 token 把 oss/ 推到 GitHub，不把凭据写进 .git/config。
#
# 用法（在 Git Bash 里）：
#   sh push.sh ghp_xxxxxxxxxxxxxxxxxxxx
#
# token 权限：Fine-grained → 只选 ExtractKit 这个仓库 → Contents: Read and write
#            （classic token 就勾 repo + workflow）
# 推完立刻去 GitHub 撤销该 token。

set -e
TOKEN="${1:?用法: sh push.sh <TOKEN>}"
REPO="qq2770355800/ExtractKit"
cd "$(dirname "$0")"

git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$REPO.git"

echo "→ 目标仓库 $REPO ，分支 $(git branch --show-current)，提交 $(git rev-parse --short HEAD)"
echo "→ 文件数 $(git ls-files | wc -l)"

git -c credential.helper= push "https://x-access-token:$TOKEN@github.com/$REPO.git" HEAD:main

git remote set-url origin "https://github.com/$REPO.git"
echo "✓ 推送完成：https://github.com/$REPO"
echo "  记得去 GitHub 撤销这次用的 token。"
