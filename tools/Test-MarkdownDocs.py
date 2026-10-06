#!/usr/bin/env python3
"""Documentation checks (read-only): unclosed code fences and broken relative links
in every tracked *.md. Mirrors ScubaGear's markdown syntax check, without a third-party action."""
import re, subprocess, sys, os
files = subprocess.check_output(['git','ls-files','*.md'], text=True).split()
bad = []
for f in files:
    text = open(f, encoding='utf-8').read()
    fences = [l for l in text.splitlines() if re.match(r'\s*(```|~~~)', l)]
    if len(fences) % 2:
        bad.append(f'{f}: unclosed code fence')
    body = re.sub(r'(```|~~~).*?\1', '', text, flags=re.S)
    for m in re.finditer(r'\]\(([^)\s#]+)(#[^)]*)?\)', body):
        t = m.group(1)
        if re.match(r'[a-z]+:', t) or t.startswith('mailto'):
            continue
        p = os.path.normpath(os.path.join(os.path.dirname(f), t))
        if not os.path.exists(p):
            bad.append(f'{f}: broken link {t}')
print('\n'.join(bad) or f'{len(files)} markdown files OK')
sys.exit(1 if bad else 0)
