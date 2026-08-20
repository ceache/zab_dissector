# ZooKeeper & ZAB Wireshark Dissector Test Suite

This directory contains automated capture fixtures, baseline golden outputs, and the test runner for the `zab.lua` Wireshark dissector.

## Test Runner Usage

To execute the test suite across all capture fixtures:

```bash
python3 tests/run_tests.py
```

To update golden baseline outputs (`instance_N.txt`) after making intentional dissector changes:

```bash
python3 tests/run_tests.py -u
```

---

## Available Test Capture Fixtures

All fixtures in `tests/fixtures/` were extracted from authentic ZooKeeper client capture runs (`kazoo-capture-runs`).

| OpCode Name | OpCode ID | Fixture Directory | Instances | Captured Response Payload Types | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CONNECT` / `CREATESESSION` | -10 / 0 | `tests/fixtures/connect` | 1 | `ConnectResponse` (protocolVersion, timeOut, sessionId, passwd, readOnly) | Session initialization and handshake |
| `CREATE` | 1 | `tests/fixtures/create` | 4 | `CreateResponse` (path), Error responses | Node creation requests & responses |
| `DELETE` | 2 | `tests/fixtures/delete` | 2 | Void / Error responses | Node deletion requests & responses |
| `EXISTS` | 3 | `tests/fixtures/exists` | 3 | `ExistsResponse` (`Stat` struct) | Node existence checks with stat return |
| `GETDATA` | 4 | `tests/fixtures/get_data` | 4 | `GetDataResponse` (data buffer, `Stat` struct) | Node data retrieval with stat return |
| `SETDATA` | 5 | `tests/fixtures/set_data` | 1 | `SetDataResponse` (`Stat` struct) | Node data update with stat return |
| `GETACL` | 6 | `tests/fixtures/get_acl` | 1 | `GetACLResponse` (vector<`ACL`>, `Stat` struct) | ACL list retrieval for znodes |
| `SETACL` | 7 | `tests/fixtures/set_acl` | 1 | `SetACLResponse` (`Stat` struct) | ACL update for znodes |
| `GETCHILDREN` | 8 | `tests/fixtures/get_children` | 1 | `GetChildrenResponse` (vector<string> children) | Child znode name listing |
| `SYNC` | 9 | `tests/fixtures/sync` | 1 | `SyncResponse` (path) | Asynchronous sync requests |
| `PING` | 11 / -2 | `tests/fixtures/ping` | 1 | `PingResponse` (empty) | Keepalive ping requests & responses |
| `GETCHILDREN2` | 12 | `tests/fixtures/get_children2` | 1 | `GetChildren2Response` (vector<string> children, `Stat` struct) | Child znode listing with stat return |
| `MULTI` | 14 | `tests/fixtures/multi` | 2 | `MultiResponse` (vector<`MultiOp`> results) | Transactional multi-operation batch |
| `CREATE2` | 15 | `tests/fixtures/create2` | 1 | `Create2Response` (path, `Stat` struct) | Node creation with stat return |
| `RECONFIG` | 16 | `tests/fixtures/reconfig` | 1 | `ReconfigResponse` (data buffer, `Stat` struct) | Dynamic cluster reconfiguration |
| `SETAUTH` | 100 | `tests/fixtures/set_auth` | 1 | `SetAuthResponse` (empty / result) | Client authentication payload |
| `SASL` | 102 | `tests/fixtures/sasl` | 1 | `SetSASLResponse` (token buffer) | SASL authentication handshake |

---

## Missing Opcode Test Data

The following opcodes are fully implemented in `zab.lua` according to upstream Apache ZooKeeper `zookeeper.jute` specifications, but do **not** have PCAP capture fixtures in `tests/fixtures/` as they are not produced by standard Kazoo Python client capture runs:

| OpCode Name | OpCode ID | Jute Request Record | Jute Response Record | Introduced Version | Note / Missing Data Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CHECKWATCHES` | 17 | `CheckWatchesRequest` (`path`, `type`) | Void (Empty) | ZooKeeper 3.5.0 | Watch checking API; no capture in standard client runs |
| `REMOVEWATCHES` | 18 | `RemoveWatchesRequest` (`path`, `type`) | Void (Empty) | ZooKeeper 3.5.0 | Watch removal API; no capture in standard client runs |
| `CREATE_CONTAINER` | 19 | `CreateContainerRequest` (`path`, `data`, `acl`, `flags`) | `CreateContainerResponse` (`path`) | ZooKeeper 3.5.3 | Container znode creation opcode |
| `CREATE_TTL` | 21 | `CreateTTLRequest` (`path`, `data`, `acl`, `flags`, `ttl`) | `CreateTTLResponse` (`path`) | ZooKeeper 3.5.3 | TTL znode creation opcode |
| `GETEPHEMERALS` | 103 | `GetEphemeralsRequest` (`prefixPath`) | `GetEphemeralsResponse` (vector<string>) | ZooKeeper 3.6.0 | Session ephemerals query opcode |
| `GETALLCHILDRENNUMBER` | 104 | `GetAllChildrenNumberRequest` (`path`) | `GetAllChildrenNumberResponse` (`totalNumber`) | ZooKeeper 3.6.0 | Recursive child count query opcode |
| `ADDWATCH` | 106 | `AddWatchRequest` (`path`, `mode`) | Void (Empty) | ZooKeeper 3.6.0 | Persistent / recursive watch opcode |
| `WHOAMI` | 107 | `WhoAmIRequest` (Empty) | `WhoAmIResponse` (vector<`ClientInfo`>) | ZooKeeper 3.6.0 | Client identity query opcode |

*Note*: Dissection logic for these 8 opcodes in `zab.lua` has been verified directly against `zookeeper.jute` definitions. Future capture runs against ZooKeeper 3.6+ clusters can add `.pcapng` fixtures to populate these folders.
