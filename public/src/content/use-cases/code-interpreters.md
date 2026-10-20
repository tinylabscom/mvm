---
title: Run user-submitted code outside your application
description: Add a code interpreter for calculations and data exploration while keeping execution out of your application server’s process.
team: Product engineering
outcome: Separate user code from the host
order: 2
guide: /examples/code-interpreter/
guideLabel: Build a bounded code interpreter
---

## The situation

Your product lets users write Python to transform a dataset or explore a calculation. Executing that source inside the web server gives user code access to the same process environment as your application.

## A workflow with mvm

1. Accept source and explicitly selected input files through your application.
2. Enforce input size limits, then submit the code to a guest with a timeout.
3. Capture and bound stdout and stderr before returning results.
4. Use a fresh guest for stateless requests. Choose a named VM only when you intentionally want files and session state to survive between cells.

For example, an analytics product could let a customer test a transformation against an uploaded CSV without running that transformation in its API server.

## What your team gains

Execution has a separate lifecycle from the request handler. Your application decides which inputs enter the guest and which results leave it, rather than sharing its own runtime with submitted code.

## What to plan for

A microVM is not a complete multi-tenant service. Your application still owns authentication, quotas, scheduling, input limits, and safe output rendering. Disable networking unless the workflow needs it, keep host credentials out of arguments, and explicitly decide when to delete session state.
