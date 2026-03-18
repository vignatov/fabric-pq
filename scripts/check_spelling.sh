#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -euo pipefail

# Sometimes the git diff returns an empty list; grep returns 1 in this case, and
# the set -e will fail the script

# "catch exit status 1" grep wrapper
c1grep() { grep "$@" || test $? = 1; }

EXCLUDE_FILE_PATTERN="^CHANGELOG|\.git|\.png$|^vendor/"
CHECK=$(git diff --name-only HEAD -- * | c1grep -Ev $EXCLUDE_FILE_PATTERN)

if [[ -z "$CHECK" ]]; then
   CHECK=$(git diff-tree --no-commit-id --name-only -r HEAD^..HEAD | c1grep -Ev $EXCLUDE_FILE_PATTERN)
fi

echo "Checking changed go files for spelling errors ..."
MISSPELL_CMD=$(command -v misspell || true)
if [[ -z "$MISSPELL_CMD" && -x "$(go env GOPATH)/bin/misspell" ]]; then
    MISSPELL_CMD="$(go env GOPATH)/bin/misspell"
fi

if [[ -z "$MISSPELL_CMD" ]]; then
    echo "misspell binary not found on PATH or at \$(go env GOPATH)/bin/misspell"
    exit 1
fi

errs=$(echo "$CHECK" | xargs "$MISSPELL_CMD" -source=text)
if [ -z "$errs" ]; then
    echo "spell checker passed"
    exit 0
fi
echo "The following files are have spelling errors:"
echo "$errs"
exit 0
