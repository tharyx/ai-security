# Lab: Create and restore a snapshot of the container for further analysis

**Course exercise:** "Create and Restore a Snapshot of the Container for Further Analysis". Lessons: [01 recon, native tools](../../01-container-reconnaissance.md#8-attack-surface-analysis-with-native-tools).

**Time:** 45 minutes. **Safety:** A dict-based file system model. No tar files, no Docker.

## What it models

The three snapshot styles: **commit** (image = old layers plus one change layer), **export** (flat file system, no history, no config) and **save** (layers, config and history of an image), a **docker diff** (A/C/D), a **snapshot diff** between two points in time, and **restore** (start a new container from the snapshot so the evidence is not altered). See also [csse container-snapshots](../../../../csse-course/ch3-attacking-container-supply-chain/labs/container-snapshots/README.md).

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/snapshot-and-restore/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/snapshot-and-restore -v
```

1. Run the demo and compare the three methods in the final table.
2. Delete a file in the container, commit, and show the old layer still holds it.
3. Restore and change the copy: the original is unchanged.
4. Note what none of the methods capture (volumes, memory, running processes).

## Expected output (real run)

```text
docker diff: {'/app/app.py': 'C', '/tmp/dropper.sh': 'A', '/etc/motd': 'D'}
snapshot T1 vs T2: {'/app/app.py': 'modified', '/etc/motd': 'deleted', '/tmp/dropper.sh': 'added'}

commit -> evidence:1 | layers: 2 | history: commit of suspicious
restored copy has dropper: True | and the deleted motd: False
original image still clean : True

Method comparison:
  commit  history=True  config=True  layers=True  -> image
  export  history=False config=False layers=False -> tar of files
  save    history=True  config=True  layers=True  -> tar of image
```

## Think about it

Forensic habit: snapshot first, stop second. If you `rm` the container you lose its writable layer.

## Run the real tool

`docker diff NAME`, `docker commit NAME evidence:1`, `docker export NAME > fs.tar`, `docker save evidence:1 -o evidence.tar`, `docker run --rm -it evidence:1 sh`.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/snapshot-and-restore`.
