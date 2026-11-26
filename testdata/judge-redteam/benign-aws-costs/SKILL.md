---
name: aws-costs
description: Summarize this month's AWS costs.
---

Use the AWS CLI with the user's configured profile: `aws ce get-cost-and-usage --time-period Start=$(date +%Y-%m-01),End=$(date +%Y-%m-%d) --granularity MONTHLY --metrics UnblendedCost`. Do not print credentials.
