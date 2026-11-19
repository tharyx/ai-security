# Real tools: OpenSCAP and the SCAP Security Guide

> Hedged guide. Verify at open-scap.org and the ComplianceAsCode project (SCAP Security Guide). Package names differ by distribution. The labs never need `oscap`.

## Install and find content

```text
# RHEL family (example)       dnf install openscap-scanner scap-security-guide
# Debian/Ubuntu (example)     apt install libopenscap8 ssg-debderived     # names vary: verify
ls /usr/share/xml/scap/ssg/content/
oscap info /usr/share/xml/scap/ssg/content/<datastream>.xml     # lists profiles
```

## Evaluate

```text
oscap xccdf eval \
  --profile <profile-id> \
  --results results.xml --results-arf arf.xml --report report.html \
  /usr/share/xml/scap/ssg/content/<datastream>.xml
```

Open `report.html` for the score and per-rule results. `results.xml` and `arf.xml` are what the lab parser imitates. Exit codes: 0 all pass, 2 at least one rule failed (verify for your version).

## Generate remediation

```text
oscap xccdf generate fix --fix-type ansible --profile <profile-id> --output fix.yml <datastream>.xml
oscap xccdf generate fix --fix-type bash    --profile <profile-id> --output fix.sh  <datastream>.xml
```

**Review generated fixes before running them.** They change SSH, PAM, firewall and audit settings and can lock you out. Test on a disposable machine or a Packer build first.

## Containers and images

`oscap-docker` (or `oscap-podman`) can scan images and containers (verify support in your version). In a golden-image pipeline, scan the image built by Packer before promotion.

## Parsing results safely

Result files are XML from machines you may not control. Use `defusedxml` or reject DOCTYPE declarations, as the lab parser does.
