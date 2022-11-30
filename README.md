CVE-2020-7461 Reproducer PoC
============================

Authors: Moshe Kol, Shlomi Oberman

Reproducer PoC for FreeBSD dhclient heap-based buffer overflow vulnerability when parsing DHCP option 119 (CVE-2020-7461).

The problem resides in the function `find_search_domain_name_len` in the file `sbin/dhclient/options.c`.
This function is called by `expand_domain_search` when DHCP option 119 (domain search, RFC 3397) is supplied from the server.
When a compression scheme is used, the function `find_search_domain_name_len` is called recursively starting from the pointed
location, but fails to check the return value of the recursive call. If the recursive call fails, a return value of -1 is used,
which is simply added to the cummulative length variable.
Here's the buggy code (lines 299-301, options.c, last commit 70066b9):
```
299:			pointed_len = find_search_domain_name_len(option,
300:			    &pointer);
301:			domain_name_len += pointed_len;
```
Later in the function `expand_domain_search`, a buffer is allocated with the length computed using `find_search_domain_name_len`,
and then the expanded name is written to this buffer using the function `expand_search_domain_name`. Since the latter function does
not have any checks on the pointer value in the compression scheme, it is possible to overrun the allocated buffer.

You can find FreeBSD Security Advisory [here](https://www.freebsd.org/security/advisories/FreeBSD-SA-20:26.dhclient.asc).

