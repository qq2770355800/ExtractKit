import pathlib, re, sys

ok = True
for f in sorted(pathlib.Path('app/src/main/kotlin').rglob('*.kt')):
    s = f.read_text(encoding='utf-8')
    # crude: remove raw strings, line comments, block comments, normal strings
    t = re.sub(r'"""(?:.|\n)*?"""', '""', s)
    t = re.sub(r'//[^\n]*', '', t)
    t = re.sub(r'/\*(?:.|\n)*?\*/', '', t)
    t = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', t)
    t = re.sub(r"'(?:\\.|[^'\\\n])*'", "''", t)
    for pair in [('{', '}'), ('(', ')'), ('[', ']')]:
        a, b = t.count(pair[0]), t.count(pair[1])
        if a != b:
            print('UNBALANCED', f.name, pair, a, b)
            ok = False
    for i, line in enumerate(s.splitlines(), 1):
        if re.search(r'\$[A-Za-z_]', line):
            print('INTERP', f'{f.name}:{i}', line.strip()[:100])
print('BALANCE OK' if ok else 'BALANCE FAIL')
