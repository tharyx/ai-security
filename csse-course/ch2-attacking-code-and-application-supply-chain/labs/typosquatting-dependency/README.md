# Lab: Typosquatting dependency

**Course exercise:** "Typosquatting dependency". Lessons: [03 section 5-9](../../03-supply-chain-attacks-on-package-managers.md#5-typosquatting). Related: [CAISP ch6 package-vetting](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/vetting.py), [CAASE skill-vetting](../../../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/skill-vetting/README.md).

**Time:** 30 minutes. **Safety:** names only. Nothing is installed or downloaded. The "popular" list is a small fixture.

## What the detector checks (`detector.py`)

| Kind | Rule |
|---|---|
| **typosquat** | Levenshtein distance 1 (names under 8 characters) or up to 2 (longer), or two adjacent letters swapped |
| **homoglyph** | equal to a popular name once look-alikes are mapped (`0`->`o`, `1`->`l`, `rn`->`m`, `vv`->`w`) |
| **combosquat** | popular name plus a trusted-sounding prefix or suffix (`-utils`, `python-`, `-official`) |
| **brandjack** | contains a vendor brand (`aws`, `github`...) but is not a known package |

Names are normalized first (case, and `-` `_` `.` treated as the same), like PyPI does.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/typosquatting-dependency/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/typosquatting-dependency
```

## Expected output (real run)

```text
reqeusts           typosquat   -> requests     2 edit(s) away from requests
numpyy             typosquat   -> numpy        1 edit(s) away from numpy
colourama          typosquat   -> colorama     1 edit(s) away from colorama
djang0             homoglyph   -> django       looks like the popular name when look-alike characters are mapped
rnatplotlib        homoglyph   -> matplotlib   looks like the popular name when look-alike characters are mapped
pandas-utils       combosquat  -> pandas       pandas combined with 'utils'
python-requests    combosquat  -> requests     requests combined with 'python'
aws-cli-helper     brandjack   -> aws          contains the brand 'aws' but is not a known official package
```

## Break it yourself

1. Add `requests-toolbelt` (a real, legitimate project) to the requirements. Is it flagged? (Not by these rules, but a rule list with `-tools` style affixes would flag legitimate names. Heuristics need an allowlist of known-good neighbours.)
2. Try a name with a Unicode lookalike letter. (Package indexes usually restrict names to ASCII, but display and chat surfaces do not. Where would this matter? Display names, repo owners, extension names.)
3. Add a rule for "name appeared in the last 7 days and has a download count near zero". Which data source do you need? (The registry's API; the lab has none.)

## Limits

Name similarity is a **signal, not proof**. Combine it with publisher age, maintainer history, install scripts and download data, and with the human question "did I mean to install this?". An LLM-hallucinated name (slopsquatting) may not be close to any real name at all: see lesson 03 section 10.
