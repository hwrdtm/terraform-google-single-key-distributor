#!/bin/bash
OUTPUT=encrypted.json.gpg
gcloud functions call ${function} \
  --region ${region} \
  --project ${project} \
  --format="value(result)" | jq -r .encryptedKey | base64 --decode > $OUTPUT
echo "Success! Wrote encrypted key to $OUTPUT"