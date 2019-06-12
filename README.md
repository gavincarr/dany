
Overview
--------

`dany` is a commandline DNS client that simulates (unreliable/semi-deprecated)
dns `ANY` queries by doing individual typed DNS queries and aggregating the
results. Queries are done concurrently for best performance.

Usage
-----

    dany [<types>] <hostname>

where `<types>` is a comma-separated list of DNS record types to query.
If unspecified, the default `types` list is: `NS,A,AAAA,MX,TXT`.

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

Licence
-------

MIT. See `LICENCE`.


Author
------

Gavin Carr <gavin@openfusion.com.au>

