# Rule reference

Rules live in [`rules/detections/`](../rules/detections), one rule per `.yaml` file. The agent
(`edr-agent rules check`) and the server load and validate them with the same checks; unknown
keys, operators, fields and event types are errors, not warnings.

```yaml
id: encoded-powershell            # [a-z0-9][a-z0-9-]{1,63}, unique
title: PowerShell launched with an encoded command
description: 'Optional longer text.'
severity: high                    # low | medium | high | critical
points: 40                        # optional 0-100; default from severity (10/25/40/60)
attack: [T1059.001, T1027]        # optional MITRE ATT&CK technique ids
event_types: [process_create]     # one or more event types (below)
condition:                        # all / any / not, nested up to 16 levels, or a leaf
  all:
    - field: image_name
      equals: [powershell.exe, pwsh.exe]
    - field: decoded_command
      exists: true
```

## Event types

`process_create`, `process_terminate`, `image_load`, `process_access`, `file_create`,
`file_delete`, `file_rename`, `registry_create`, `registry_set`, `registry_delete`,
`registry_rename`, `network_connect`, `dns_query`.

Sysmon event IDs map as: 1 process_create, 3 network_connect, 5 process_terminate,
7 image_load, 10 process_access, 11 file_create, 12 registry_create / registry_delete,
13 registry_set, 14 registry_rename, 22 dns_query, 23 and 26 file_delete. ETW: Kernel-Process
1/2, Kernel-Network 12/28 (TCP connect, IPv4/IPv6), DNS-Client 3008. `file_rename` exists in
the model for replayed data; neither collector produces it yet.

## Fields

Collector fields: `host`, `source`, `type`, `pid`, `ppid`, `image`, `command_line`, `user`,
`integrity_level`, `hashes`, `process_guid`, `parent_process_guid`, `parent_image`,
`parent_command_line`, `target_path` (file or registry path), `new_path`, `details` (registry
value data), `registry_event_type`, `target_image`, `granted_access`, `image_loaded`, `signed`,
`signature`, `protocol`, `initiated`, `src_ip`, `src_port`, `dest_ip`, `dest_port`,
`dest_hostname`, `query_name`, `query_status`, `query_results`.

Enrichment added by the engine before rules run (never taken from input):

| Field | Meaning |
|---|---|
| `image_name` | lower-case file name of `image` |
| `parent_image` / `parent_image_name` | from the event, or from the process table |
| `ancestor_images` | list of ancestor image paths, nearest first (string operators match any element) |
| `decoded_command` | the decoded `-EncodedCommand` script, when one decodes |
| `encoded_command_error` | why decoding failed (`invalid base64`, `invalid utf-16le`, `payload too large`, `missing payload`) |

Values are compared as text (integers in decimal, booleans as `true`/`false`). An empty string
counts as absent. A leaf on an absent field is false, except `exists: false`; so
`not: {field: dest_ip, cidr: [...]}` is true when there is no `dest_ip`.

## Operators

| Operator | Value | Notes |
|---|---|---|
| `equals`, `contains`, `startswith`, `endswith` | string or list (any matches) | ASCII case-insensitive unless `case_sensitive: true` |
| `regex` | string | ECMAScript / Python `re` subset; case-insensitive by default; subject truncated to 4096 bytes |
| `gt`, `gte`, `lt`, `lte` | integer | field parsed as a decimal integer |
| `exists` | `true` / `false` | |
| `cidr` | CIDR string or list | IPv4 and IPv6; a non-IP value never matches |
| `min_label_length` | integer | length in bytes of the longest dot-separated label |
| `min_label_entropy` | number 0-8 | Shannon entropy (bits per byte) of the longest label |

Keep regexes to the common subset of ECMAScript and Python (no look-behind, no named groups,
no possessive quantifiers); the parity tests run every shipped rule in both engines.

## Encoded-command decoding

For any event with a command line, the engine looks for the first token that is `-` or `/`
followed by a prefix of `encodedcommand` (`-e`, `-en`, `-enc`, ..., or `-ec`), any case. The
next token (double quotes removed) must be at most 64 KiB of standard Base64 (padding optional)
that decodes to an even number of bytes forming valid UTF-16LE without NUL characters. Anything
else sets `encoded_command_error` instead of `decoded_command`.

## YAML subset

The C++ agent has no YAML library dependency; it reads a documented subset: block mappings and
sequences, single-line flow sequences of scalars, plain / single- / double-quoted scalars and
comments. Values that YAML 1.1 parsers such as PyYAML would turn into surprising types
(`yes`/`no`/`on`/`off`, `0x10`, `012`, `1:30`, dates, `.5`) are rejected with a "quote it"
message. `edr-agent rules dump` prints the parsed files as JSON, and a server test checks that
the result equals what PyYAML reads.

## Adding a rule

1. Add `rules/detections/<id>.yaml`.
2. Add at least one positive and one negative case to `rule_cases()` in
   `samples/tools/generate_samples.py` and regenerate the samples.
3. Run `edr-agent rules check`, `ctest` and `pytest`; both test suites require a positive and a
   negative case for every rule.
4. If the rule should combine with others, add a correlation in `rules/scoring.yaml`.
