import pathlib, sys

BS = chr(92)  # backslash, 避免 heredoc 吃掉转义


def scan(path):
    src = pathlib.Path(path).read_text(encoding='utf-8')
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            while i < n and src[i] != chr(10):
                i += 1
        elif c == '/' and i + 1 < n and src[i + 1] == '*':
            i += 2
            while i + 1 < n and not (src[i] == '*' and src[i + 1] == '/'):
                i += 1
            i += 2
        elif c == '"':
            i += 1
            while i < n:
                if src[i] == BS:
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
        elif c == "'":
            i += 1
            while i < n:
                if src[i] == BS:
                    i += 2
                    continue
                if src[i] == "'":
                    i += 1
                    break
                i += 1
        else:
            out.append(c)
            i += 1
    code = ''.join(out)
    return code.count('{'), code.count('}'), code.count('('), code.count(')')


for p in sys.argv[1:]:
    ob, cb, op, cp = scan(p)
    flag = 'OK' if ob == cb and op == cp else 'MISMATCH'
    print(f"{p}: braces {ob}/{cb} parens {op}/{cp}  {flag}")
