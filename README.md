
Overview
--------

`dany` is a commandline DNS client that simulates (unreliable/semi-deprecated)
dns `ANY` queries by doing individual typed DNS queries and aggregating the
results. Queries are done concurrently for best performance.

Usage
-----

    dany [<types>] <hostname>

where `<types>` is a comma-separated list of DNS record types to query.
If unspecified, the default `types` list is: `SOA,NS,A,AAAA,MX,TXT`.

In the output, fields are separated by tabs, so you can use `cut` (with no
delimiter) to extract individual fields.

Examples:

```
$ dany cisco.com
A               72.163.4.185
AAAA            2001:420:1101:1::185
MX      10      alln-mx-01.cisco.com.
MX      20      rcdn-mx-01.cisco.com.
MX      30      aer-mx-01.cisco.com.
NS              ns1.cisco.com.
NS              ns2.cisco.com.
NS              ns3.cisco.com.
SOA             ns1.cisco.com.      postmaster.cisco.com.
TXT             926723159-3188410
TXT             MS=ms35724259
TXT             docusign=5e18de8e-36d0-4a8e-8e88-b7803423fa2f
TXT             docusign=95052c5f-a421-4594-9227-02ad2d86dfbe
TXT             facebook-domain-verification=qr2nigspzrpa96j1nd9criovuuwino
TXT             google-site-verification=K2w--6oeqrFjHfYtTsYyd2tFw7OQd6g5HJDC9UAI8Jk
TXT             google-site-verification=PdOwpBvoBbr90361WK-DzUDRAwNMWd2f4jqgvGKlpWg
TXT             google-site-verification=lW5eqPMJI4VrLc28YW-JBkqA-FDNVnhFCXQVDvFqZTo
TXT             v=spf1 redirect=spfa._spf.cisco.com
TXT             zpSH7Ye/seyY61hH8+Rq5Kb+ZJ9hDa+qeFBaD/6sPAAg+2POkGdP0byHb1pFVK9uZgYF2AIosUSZq4MB17oydQ==

$ dany mx,txt google.com
MX      10      aspmx.l.google.com.
MX      20      alt1.aspmx.l.google.com.
MX      30      alt2.aspmx.l.google.com.
MX      40      alt3.aspmx.l.google.com.
MX      50      alt4.aspmx.l.google.com.
TXT             docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e
TXT             facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95
TXT             globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=
TXT             v=spf1 include:_spf.google.com ~all
```

The `-w/--www` flag additionally probes the `www.<hostname>` label. By default
only A and AAAA are queried for the www label; if `-t/--types` (or `-a/--all`)
is given explicitly, that set is used for the www probe too. With `-T/--tag`,
apex and www results are emitted on separate lines tagged with their
hostname; without it, they share the same output and identical rows are
collapsed (so a www that resolves to the same IP as the apex won't appear
twice).

```
$ dany -w -T google.com
google.com              A               172.217.25.110
google.com              AAAA            2404:6800:4006:80d::200e
google.com              MX      10      smtp.google.com.
google.com              NS              ns1.google.com.
google.com              NS              ns2.google.com.
google.com              NS              ns3.google.com.
google.com              NS              ns4.google.com.
google.com              SOA             ns1.google.com. dns-admin.google.com.
google.com              TXT             v=spf1 include:_spf.google.com ~all
www.google.com          A               142.251.150.119
www.google.com          AAAA            2404:6800:4006:80d::2004
```

The `-f/--fmt` flag selects the output format: `text` (default, the
tab-separated form shown above), `json`, or `yaml` (`yml` as a convenience
alias). In `json` and `yaml` modes:

- Each record carries both `rdata` (the canonical DNS presentation form,
  always a string) and `data` (a typed per-RR-type payload — `address`
  for A/AAAA, `preference`+`exchange` for MX, full RFC field set for SOA,
  `strings` array for TXT, etc.).
- A `schema_version: 1` envelope wraps the per-hostname output. Multi-
  hostname runs emit NDJSON (one object per line) in `json` mode and
  multi-document YAML (`---`-separated) in `yaml` mode.
- Errors fold into the envelope's `errors` field with a stable machine-
  readable `code` (`NXDOMAIN`, `SERVFAIL`, `EXCHANGE_ERROR`, …) — nothing
  goes to stderr.
- PTR records (when `-p/--ptr` is set) appear as standalone entries with
  the source IP carried in `data.ip` for easy joining (text mode folds
  them into the matching A/AAAA row instead).

```
$ dany -f json -t a,mx example.com
{"schema_version":1,"query":{"hostname":"example.com","types":["a","mx"],
"server":"8.8.8.8:53","options":{"www":false,"usd":false,"ptr":false}},
"answers":[{"type":"A","name":"example.com.","ttl":86400,"class":"IN",
"rdata":"96.7.128.198","data":{"address":"96.7.128.198"}}],"errors":[]}

$ dany -f yaml -t mx example.com
---
schema_version: 1
query:
  hostname: example.com
  types:
    - mx
  server: 8.8.8.8:53
  options:
    www: false
    usd: false
    ptr: false
answers:
  - type: MX
    name: example.com.
    ttl: 86400
    class: IN
    rdata: 10 mx.example.com.
    data:
      preference: 10
      exchange: mx.example.com.
errors: []
```

Author
------

Gavin Carr <gavin@openfusion.net>


Licence
-------

MIT. See `LICENCE`.

