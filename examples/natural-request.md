# Deliver a note through an enrolled approval route

Illustrative interaction, not a recorded successful write or human usability study.

## Input and natural request

The operator has started Sentinel and enrolled `reviewed` as an ask destination.
Facts: a batch started at 09:00 and stopped at 09:12 after input validation failed.

> Prepare a short incident note from these facts. Use Sentinel to deliver it to
> the operator-enrolled reviewed slot, then verify the readback.

## What should happen

1. The assistant prepares accurate UTF-8 text within the route's size limit.
2. It calls the discovered `write_artifact` tool for the enrolled slot.
3. The separate operator decides on the exact text. The assistant waits for the
   actual tool outcome; it does not approve itself.
4. Only a real successful receipt establishes creation. The assistant checks
   `slot`, `bytes`, `sha256` and `created`, and reads back when requested.

If denied, expired or unavailable, report non-delivery. Do not switch to shell
or ordinary file tools to create the same artifact. A lost response can follow
a commit: inspect before retrying. These statements are workflow expectations,
not invented tool responses.

## When to use another workflow

Ordinary report drafting, generic human approval or blocking arbitrary network
commands does not establish this specific route. Follow [setup](../README.md#start-locally)
only when setup is actually authorized; installing instructions alone does not
start Sentinel or protect other tools.
