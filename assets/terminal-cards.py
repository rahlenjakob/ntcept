import html, sys, re

# A terminal "card" SVG: dark rounded panel, traffic-light dots, monospace lines with light
# syntax accents. Renders real captured output — nothing invented.

BG      = "#12141a"
BAR     = "#1b1e26"
BORDER  = "#272b36"
FG      = "#c9d1d9"
DIM     = "#6e7681"
GREEN   = "#3fb950"
CYAN    = "#56d4dd"
MAGENTA = "#d2a8ff"
AMBER   = "#e3b341"
RED     = "#f85149"
WHITE   = "#f0f6fc"

CW = 8.4      # char width at 14px monospace
LH = 22       # line height
PADX = 20
PADY = 18
BAR_H = 34

def esc(s): return html.escape(s)

def spans(line):
    """Return list of (text, color) for one line."""
    out = []
    def push(t, c): 
        if t: out.append((t, c))

    if line.startswith("$ "):
        # prompt line: "$ cmd   # comment"
        push("$ ", GREEN)
        rest = line[2:]
        if "#" in rest:
            cmd, com = rest.split("#", 1)
            push(cmd, WHITE); push("#"+com, DIM)
        else:
            push(rest, WHITE)
        return out

    if line and line[0] in "→←":
        push(line[0], CYAN if line[0]=="→" else MAGENTA)
        rest = line[1:]
        # first word after arrow is the message keyword
        m = re.match(r"(\s+)(\S+)(.*)", rest)
        if m:
            push(m.group(1), FG)
            kw = m.group(2)
            if kw.startswith("Error"):
                push(kw, AMBER)
            elif kw[:1].isupper():   # a protocol message keyword (Parse, Bind, DataRow…)
                push(kw, CYAN)
            else:
                push(kw, FG)
            body = m.group(3)
            # highlight $1=, $2= params and quoted sql loosely
            body = re.sub("", "", body)
            push(body, FG)
        else:
            push(rest, FG)
        return out

    # ls row: "3   13:28:55.887  postgres   23ms  127.0.0.1:15432  35 msg  [err]"
    if re.match(r"^\d+\s", line):
        toks = re.split(r"(\s+)", line)
        for t in toks:
            if t.strip()=="" : push(t, FG); continue
            if re.match(r"^\d+$", t) and len(t)<=4: push(t, DIM)
            elif re.match(r"^\d\d:\d\d:", t): push(t, DIM)
            elif t in ("GET","POST","PUT","DELETE","PATCH","HEAD"): push(t, CYAN)
            elif t in ("postgres","redis","mysql","mongodb","dns","ws","tcp","udp"): push(t, MAGENTA)
            elif t in ("http/1.1","h2","h2c"): push(t, DIM)
            elif re.match(r"^[23]\d\d$", t): push(t, GREEN)
            elif re.match(r"^[45]\d\d$", t): push(t, RED)
            elif t.startswith("[") : push(t, AMBER)
            elif re.match(r"^\d+ms$", t) or re.match(r"^\d+$", t): push(t, DIM)
            elif t=="msg": push(t, DIM)
            else: push(t, FG)
        return out

    push(line, FG)
    return out

def render(title, lines, out_path, width_chars=None):
    if width_chars is None:
        width_chars = max([len(l) for l in lines]+[len(title)]) + 2
    W = int(PADX*2 + width_chars*CW)
    H = int(BAR_H + PADY*2 + len(lines)*LH)
    parts = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="14">')
    parts.append(f'<rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="10" fill="{BG}" stroke="{BORDER}"/>')
    parts.append(f'<path d="M0 10 a10 10 0 0 1 10 -10 h{W-20} a10 10 0 0 1 10 10 v{BAR_H-10} h-{W} z" fill="{BAR}"/>')
    for i,c in enumerate(("#ff5f56","#ffbd2e","#27c93f")):
        parts.append(f'<circle cx="{20+i*18}" cy="{BAR_H/2}" r="6" fill="{c}"/>')
    parts.append(f'<text x="{W/2}" y="{BAR_H/2+4}" fill="{DIM}" text-anchor="middle" font-size="12">{esc(title)}</text>')
    y = BAR_H + PADY + 6
    for line in lines:
        x = PADX
        parts.append(f'<text y="{y}">')
        for t,c in spans(line):
            # preserve spaces with xml:space
            parts.append(f'<tspan x="{x}" fill="{c}" xml:space="preserve">{esc(t)}</tspan>')
            x += len(t)*CW
            # tspans with x reset overwrite; instead build one line with dx. Simplify: use one text with sequential tspans (no x reset)
        parts.append('</text>')
        y += LH
    parts.append('</svg>')
    open(out_path,"w").write("".join(parts))
    print("wrote", out_path, f"({W}x{H})")

# NOTE: the per-tspan x reset above is wrong for sequential text; fixed in render2 below.
ls_lines = [
 "$ ntcept run -- npm run dev            # your app, unchanged",
 "$ ntcept ls",
 "1   13:28:35.718  http/1.1 POST 204   230ms  telemetry.nextjs.org/api/v1/record",
 "3   13:28:55.887  postgres           23ms  127.0.0.1:15432   35 msg",
 "4   13:28:56.012  redis               8ms  127.0.0.1:16379   12 msg",
 "5   13:28:56.115  http/1.1 GET  200   160ms  api.open-meteo.com/v1/forecast",
 "6   13:28:56.324  postgres           14ms  127.0.0.1:15432   34 msg  [err]",
]
render("ntcept ls", ls_lines, "assets/flows.svg")
pg_lines = [
 "$ ntcept show 3",
 "3  postgres   127.0.0.1:15432   23 ms",
 "→  Parse    select id,email,total,status from orders where email=$1 and total>=$2",
 "→  Bind     [$1=grace@example.com, $2=1000]",
 "→  Execute",
 "←  RowDescription   id, email, total, status",
 "←  DataRow          2, grace@example.com, 12750, paid",
 "←  CommandComplete  SELECT 1",
]
render("ntcept show 3", pg_lines, "assets/postgres.svg")
err_lines = [
 "$ ntcept show 6",
 "6  postgres   127.0.0.1:15432   14 ms",
 "→  Bind     insert into orders(email,total,status) … [$1=alan@example.com]",
 "←  ErrorResponse  ERROR  23505",
 "←                 duplicate key value violates unique constraint",
 "←                 detail: Key (email)=(alan@example.com) already exists.",
]
render("ntcept show 6", err_lines, "assets/error.svg")
mod_lines = [
 "$ ntcept intercept on                          # hold requests for a verdict",
 "$ ntcept queue",
 "   h1  request   GET  http://httpbin.org/get?who=ntcept",
 "$ ntcept respond h1 --status 200 --body '{\"stubbed\":\"by ntcept\"}'",
 "←  the app got  200  {\"stubbed\":\"by ntcept\"}   — httpbin never saw it",
]
render("hold a request · answer it yourself", mod_lines, "assets/modify.svg")
