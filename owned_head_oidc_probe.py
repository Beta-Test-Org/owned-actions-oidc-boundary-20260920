#!/usr/bin/env python3
"""Benign probe proving which repository identity GitHub assigns to fork code.

The script intentionally prints only selected JWT claims. It never prints or
persists the raw OIDC token or GitHub's request credential.
"""

import base64
import json
import os
import urllib.parse
import urllib.request


EXPECTED_SOURCE = "Jhounx/owned-actions-oidc-boundary-20260920"
EXPECTED_TARGET = "Beta-Test-Org/owned-actions-oidc-boundary-20260920"
AUDIENCE = "urn:owned-actions-lab:github-oidc-boundary"


def decode_payload(token: str) -> dict:
    encoded = token.split(".")[1]
    encoded += "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))


with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as handle:
    event = json.load(handle)

source = event["pull_request"]["head"]["repo"]["full_name"]
target = event["pull_request"]["base"]["repo"]["full_name"]
if source != EXPECTED_SOURCE or target != EXPECTED_TARGET:
    raise SystemExit("refusing to run outside the researcher-owned fork fixture")

request_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
separator = "&" if urllib.parse.urlsplit(request_url).query else "?"
request = urllib.request.Request(
    request_url + separator + urllib.parse.urlencode({"audience": AUDIENCE}),
    headers={
        "Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    },
)
with urllib.request.urlopen(request, timeout=15) as response:
    token = json.load(response)["value"]

claims = decode_payload(token)
selected_names = (
    "iss",
    "aud",
    "sub",
    "actor",
    "actor_id",
    "event_name",
    "head_ref",
    "base_ref",
    "ref",
    "repository",
    "repository_id",
    "repository_owner",
    "repository_owner_id",
    "repository_visibility",
    "workflow_ref",
    "workflow_sha",
    "job_workflow_ref",
    "job_workflow_sha",
    "runner_environment",
)
selected = {name: claims[name] for name in selected_names if name in claims}
boundary = {
    "claim_repository_is_target": claims.get("repository") == EXPECTED_TARGET,
    "event_source_is_fork": source != target,
    "event_source_repository": source,
    "event_target_repository": target,
    "head_repository_claim_present": "head_repository" in claims,
    "cloud_exchange_performed": False,
    "raw_token_printed": False,
}

print("OWNED_HEAD_CODE_EXECUTED=true")
print("OWNED_HEAD_EVENT_SOURCE=" + source)
print("OWNED_HEAD_OIDC_CLAIMS_JSON=" + json.dumps(selected, sort_keys=True))
print("OWNED_HEAD_BOUNDARY_JSON=" + json.dumps(boundary, sort_keys=True))
print("OWNED_HEAD_BRIDGE=PASS")
