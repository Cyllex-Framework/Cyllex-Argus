# TAXII 2.1 Server

_[Back to the docs index](README.md)_

## TAXII 2.1 server

Argus is a **read-write TAXII 2.1 node**, not just a consumer. External CTI tools (MISP, OpenCTI,
Microsoft Sentinel, Splunk ES, Anomali ThreatStream, …) can subscribe to this instance and poll
incrementally — or push STIX envelopes to it.

```
GET  /taxii2/                                                      discovery
GET  /taxii2/api1/                                                 API Root info
GET  /taxii2/api1/collections/                                     list collections
GET  /taxii2/api1/collections/argus/                               collection metadata
GET  /taxii2/api1/collections/argus/objects/                       STIX envelope
GET  /taxii2/api1/collections/argus/manifest/                      lighter sync bookkeeping
GET  /taxii2/api1/collections/argus/objects/{stix_id}/             one object
POST /taxii2/api1/collections/argus/objects/                       push envelope → status
GET  /taxii2/api1/status/{status_id}/                              poll POST status
```

Pagination, `added_after` for incremental sync, OASIS §3.4 server-side filters, Bearer or
`X-Argus-Token` auth, `application/taxii+json;version=2.1`. ATT&CK entities are **referenced** by
their canonical MITRE stix id but never re-emitted.


---
_[Back to the docs index](README.md)_
