# 2025-11-06 Agency: a failing transaction kills the agent (SIGSEGV)

A single `POST /_api/agency/transact` with a body whose operation is **not
`set`** — or a `set` without its `new` payload — takes the whole agent process
down. The endpoint answers nothing; the process is gone.

Found by `agency_fuzz.py` (3 000 hostile bodies at `/_api/agency/{transact,
write,read}` on a single-node agent) and then reduced by hand to one body.

## Reproduce

```sh
# single-node agent
arangod --configuration none --database.directory /tmp/ag/db \
  --server.endpoint tcp://127.0.0.1:8542 --server.authentication false \
  --javascript.startup-directory <src>/js --javascript.app-path /tmp/ag/apps \
  --agency.activate true --agency.size 1 --agency.supervision false \
  --agency.endpoint tcp://127.0.0.1:8542 --agency.my-address tcp://127.0.0.1:8542 \
  --agency.election-timeout-min 0.5 --agency.election-timeout-max 1.0

curl -X POST -H 'Content-Type: application/json' \
  --data '[[{"a": {"op": "bad"}}]]' http://127.0.0.1:8542/_api/agency/transact
```

`input.json` is that body; `report.txt` is the agent's crash log.

## What the agent says

```
FATAL {crash} caught unexpected signal 11 (SIGSEGV, sub type SEGV_MAPERR:
      address not mapped to object) ... accessing address 0x0000000000000020
      thread [SchedWorker]
  #3 arangodb::consensus::Agent::transact(arangodb::velocypack::Slice)
  #4 arangodb::RestAgencyHandler::handleTransact()
  #5 arangodb::RestAgencyHandler::executeAsync()
  #6 arangodb::rest::RestHandler::executeEngine()
```

A null pointer dereferenced at offset `0x20`, on the scheduler worker that
serves the transaction.

## Which bodies crash (measured, one fresh agent per row)

| body sent to `/_api/agency/transact` | result |
|---|---|
| `[[{"/a": {"op": "set", "new": "1"}}]]` | **200**, agent alive |
| `[[{"/a": {"op": "set"}}]]` (no `new`) | SIGSEGV |
| `[[{"/a": {"op": "del"}}]]` (unknown op) | SIGSEGV |
| `[[{"/a": {"op": "cas", "old": "0", "new": "1"}}]]` (unknown op) | SIGSEGV |
| `[[{"/a": {"op": "incr", "step": 1}}]]` (unknown op) | SIGSEGV |
| `[[{"a": {"op": "bad"}}]]` (unknown op) | SIGSEGV |

So the trigger is **a transaction that fails**: an operation name outside the
small set the store implements (`set`, `delete`, `increment`, `decrement`,
`push`, `pop`, `prepend`, `shift`, `erase`, `replace`, locks) or a `set` that is
missing its payload. A transaction that *succeeds* is fine.

## Root cause: not pinned down, and here is what is known

`Node::applyOp` (arangod/Agency/Node.cpp:451-490) returns a proper error for an
unknown operation (`Result(TRI_ERROR_FAILED, ...)`), and `Store::apply`
(arangod/Agency/Store.cpp:612-645) checks `ret.fail()` and breaks. So the null
dereference is somewhere between the REST handler and the store's error
handling — the frame points at `Agent::transact` itself, which suggests it
dereferences a result/transaction object without checking it after a failed
apply. The exact line was not resolved: `addr2line` over the 1.7 GB binary
exceeds this box's memory cap, and the offsets in the log are not source lines.

That is the one open question for a maintainer, and the reproducer above is
deterministic.

## Severity

Remote: any client that can reach the agency endpoint (`/_api/agency/transact`
is served by the agent, unauthenticated in this build) kills that agent with
~30 bytes. In a cluster that is one of the three consensus members per request,
so it is a straightforward denial of service against cluster metadata — and it
takes down the write path for everything the agency tracks.

Whether the endpoint is reachable outside a cluster network is a deployment
question, not something this finding assumes.
