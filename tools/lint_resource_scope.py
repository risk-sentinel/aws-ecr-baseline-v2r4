#!/usr/bin/env python3
"""Fail on InSpec resource calls made in a `describe` BODY.

A describe body is an RSpec example GROUP, not an example. Calling a resource
there raises at exec time:

    RSpec::Core::ExampleGroup::WrongScopeError
    `aws_ecr_repository` is not available on an example group

Neither `cinc-auditor check` nor `json` evaluates control bodies, so both pass
on the broken code. This shipped in v0.1.4 and broke the consumer's exec leg.

LEGAL, and must not be flagged:
    describe aws_ecr_repository(name: n) do   # resource is an ARGUMENT
    subject { aws_ecr_repository(name: n) }   # deferred into an example
    it { ... }  /  before  /  let

ILLEGAL:
    describe 'x' do
      aws_ecr_repository(name: n).something   # bare call in the group body
    end

Implementation note: a naive depth counter is wrong. Decrementing on every
`end` lets the `end` of an inner `it ... do` block close the describe frame,
after which the rest of the body goes unchecked — that mistake made the first
version of this linter pass the very code it was written to catch. A stack is
required so each `end` pops the frame it actually belongs to.
"""
import re
import sys
from pathlib import Path

RESOURCE = re.compile(r"\baws_[a-z0-9_]+\(")
# A block opener: a trailing `do` (with optional |args|), or a keyword that
# opens a block needing `end`. Anchored at line start so a MODIFIER form
# (`impact 0.0 if repos.empty?`) does not push a frame.
DO_BLOCK = re.compile(r"\bdo\b\s*(\|[^|]*\|)?\s*$")
KEYWORD_BLOCK = re.compile(r"^(if|unless|case|begin|def|class|module|while|until)\b")
END = re.compile(r"^end\b")
DESCRIBE = re.compile(r"^(describe|context)\b")
DEFERRED = re.compile(r"^(it|its|subject|before|after|let|let!|specify|example)\b")


def violations(path: Path):
    stack = []          # frame kinds: 'describe' | 'deferred' | 'other'
    out = []

    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        opens = bool(DO_BLOCK.search(line)) or bool(KEYWORD_BLOCK.match(line))

        if DESCRIBE.match(line):
            kind = "describe"
        elif DEFERRED.match(line):
            kind = "deferred"
        else:
            kind = "other"

        # In a describe body unless something deferred intervenes above it.
        in_group = False
        for frame in reversed(stack):
            if frame == "deferred":
                break
            if frame == "describe":
                in_group = True
                break

        # A resource on the `describe ... do` line is an ARGUMENT — legal.
        # A resource on an it/subject/let line is deferred — legal.
        if in_group and kind == "other" and RESOURCE.search(line):
            out.append((lineno, line))

        if END.match(line) and stack:
            stack.pop()
        elif opens:
            stack.append(kind)

    return out


def main(argv):
    targets = []
    for root in argv[1:] or ["controls", "libraries"]:
        targets.extend(Path(root).rglob("*.rb"))

    found = []
    for f in sorted(targets):
        for lineno, line in violations(f):
            found.append(f"{f}:{lineno}: {line[:100]}")

    if found:
        print("::error::InSpec resource called in a describe body — raises "
              "WrongScopeError at exec. Resolve it at control scope instead.")
        for f in found:
            print(f"  {f}")
        return 1

    print(f"OK — no resource calls in describe bodies ({len(targets)} file(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
