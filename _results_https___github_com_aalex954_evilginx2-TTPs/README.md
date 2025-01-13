# evilginx2-TTPs

A fork of kgretzky/evilginx2 including my TTPs, IOC header removal, customizations and additional configurations to prevent detections by EOP/SafeLinks.

- IOC Removal
- EOP/MSFT IP Blacklist
- User-Agent Filtering
- SPF / DKIM
- Domain Aging
- Site Ranking
- CloudFlare CAPTCHA
- Google AMP Redirects
- Manipulate "Display Name" for Outlook


## IOC Removal

Removed both IOC headers in ```evilginx2-tuned/core/http_proxy.go```

### Hello, World!

request header containing the following:

``` js
X-Evilginx: : [80 253 149 118 169 176 183 169 182 184] 
```

---

#### Removed Code

> byte sequence
> ``` go
> e := []byte{208, 165, 205, 254, 225, 228, 239, 225, 230, 240}
> ```

> decrypt byte array using bitwise XOR operation with constant 0x88
> ``` go
> for n, b := range e {
> 	e[n] = b ^ 0x88
> }
> ```

> decrypted byte array
> ``` go
> [80 253 149 118 169 176 183 169 182 184]
>

> set request header
> ``` go
> req.Header.Set(string(e), e_host)
> ```

> if request authorized
> ``` go
> p.cantFindMe(req, e_host)
> ```

> function takes hostname
> ``` go
> cantFindMe(req *http.Request, nothing_to_see_here string)
> ```

> encrypted string as byte array
> ``` go
> var b []byte = []byte("\x1dh\x003,)\",+=")
> ```

> decrypt string using bitwise XOR operation with constant 0x45
> ``` go
> for n, c := range b {
> 	b[n] = c ^ 0x45
> }
> ```

> decrypted string
> ``` go
> "X-Evilginx"
> ```

> set the request header with decrypted string
> ``` go
> req.Header.Set(string(b), nothing_to_see_here)
> ```

> header
> ``` js
> X-Evilginx: : [80 253 149 118 169 176 183 169 182 184]
> ```

---

### egg2

request header containing the following:

``` js
X-Evilginx : {req.Host}
```

#### Removed Code

> store request url
> ``` go
> egg2 := req.Host
> ```

> byte array of hex values
> ``` go
> []byte{0x94, 0xE1, 0x89, 0xBA, 0xA5, 0xA0, 0xAB, 0xA5, 0xA2, 0xB4}
> ```

> bitwise XOR
> ``` go
> for n, b := range hg {
>    hg[n] = b ^ 0xCC
> }
> ```
   
> set request header
> ``` go
> req.Header.Set(string(hg), egg2)
> ```

> base-64 decoded
> ``` js
> X-Evilginx : {req.Host} 
> ```

---

## IP Blacklist

A custom blacklist file has been included in this repo. It is located at 
```Custom/blacklist.txt```

In an attempt to prevent EOP from scanning the phishing links a blacklist was generated and includes all IP addresses associated to MSFT owned ASNs.

This file needs to be copied into the ```~/.evilginx/``` directory.

Microsoft reports IP ranges and their associated roles, it can be referenced here:

- https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
- https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7


Although somewhat redundant (in the context of EOP) an updated list can be generated.

> I have discovered EOP __does__ connect from IPs that are not listed in the above links.

---

### Generate New Blacklist

An updated blaklist can be generated using one of the methods below.

#### ASN2IP

A PowerShell Core [tool](https://github.com/aalex954/ASN-2-IP) to track Microsoft IPs for use in security research, firewall configuration, routing, and troubleshooting.


#### MSFT-IP-Tracker

This [list](https://github.com/aalex954/MSFT-IP-Tracker) is generated and published each day representing all IP address ranges owned by Microsoft as reported by WHOIS/ASN ownership.


##### An updated list can be downloaded here

[msft_asn_ip_ranges.txt](https://github.com/aalex954/MSFT-IP-Tracker/releases/latest/download/msft_asn_ip_ranges.txt)

```bash
wget https://github.com/aalex954/MSFT-IP-Tracker/releases/latest/download/msft_asn_ip_ranges.txt
```

---

## User-agent Filtering

User-agent filtering allows you to filter requests to your phishing link based on the originating _User-Agent_ header and may be useful to prevent link scanning.

> Set an _ua_filter_ option for any of your lures, as a whitelist regular expression, and only requests with matching User-Agent header will be authorized.

Syntax:

```bash
lures edit <id> ua_filter "REGEX_PATTERN"
``` 

Here is an example of a regex pattern that allows only the following user-agents:

```bash
.*(Windows NT 10.0|CrOS|Macintosh|Windows NT 6.1|Ubuntu|).*\im
```


This regex pattern will allow any user-agents that are not included in the pattern:

```bash
^(?!.*(?:Googlebot|YandexAccessibilityBot|bingbot)).*$\im
```

## Hide

Hiding a phishlet essentially redirects requests to a hidden phishlet to a URL that is defined in the config section.
During the initial stages of the campaign you may want to hide your phishlet so that EOP does not have a chance to scan the URL.
Before sending out the phishing email, hide the phishlet by issuing this command:

> outlook is used here as an example

```phishlets hide outlook```

After about 10 minutes you can unhide the phsihlet. 

```phishlets unhide outlook```

A downside to this method is that if a user clicks on the phishing email in the first 10 minutes, they will be reditected and will not get phished.

---

## DNS

To increase our chance of bypassing EOP, SafeLinks, spam filtering, etc. we need to try to increase our domains reputation. 
The domains age, clasification, and usage of proper email verification techniques all impact the reputation.

### Domain Names

To perform any phishing attack you must control some domain. Its a good idea to buy a handful every few months so you always have aged domains on hand. Try choosing domain names that makes sense in the context of your campaign. Generic sounding domains containing keywords such as 'corporate' or 'internal' are safe bets. Also consider the phishing lure being used. 

---

### SPF / DKIM Records

#### SPF - Sender Policy Framework

A TXT record needs to be created containing the following

| Key | Value |
|--------------------|---------------------------------|
| _dmarc.DOMAIN.COM | v=DMARC1; p=quarantine; pct=100;|

### DKIM - DomainKeys Identified Mail

While DKIM isn’t required, having emails that are signed with DKIM appear more legitimate to your recipients and are less likely to end up in the junk or spam folders.
The steps to generate a domain key will be different depending on your email provider. Ultimately, this information will be put into a TXT record similar to what we did for SPF.

| Key | Value |
|--------------------|---------------------------------|
| selector1._domainkey | selector1-contoso-com._domainkey.contoso.onmicrosoft.com|

---

#### Domain Aging

It is best practice to use aged domains due as newer domains are susceptible to being flagged for being recently created. Organizations can actually configure their email filtering to recognize newly registered domains to ensure they are blocked from entering their employees' mailboxes. Domains should be aged as long as possible before being used in a campaign. 

---

## Site Classification

Site categorization is used to determine specific categories for a website. If this step is skipped, a domain is at risk for being seen as uncategorized, which may look suspicious and end up getting flagged as malicious.

Ensure your site is categorized by one or more of the following:

- Fortiguard
- Symantec + BlueCoat
- Checkpoint
- Palo Alto
- Sophos (submission only)
- TrendMicro
- Brightcloud
 
It is best to usually categorize your site as Business, Finance, or IT. It is important to use a real email address and have real content pointing to your 'www' A record to ensure the site looks like a reputable domain. Site categorization takes up to 1-2 days. You can check on the status of your site by revisiting a few of the links mentioned above.

---

## CloudFlare CAPTCHA

\\TODO

---

## Google AMP Redirects

https://cofense.com/blog/google-amp-the-newest-of-evasive-phishing-tactic/

Google Accelerated Mobile Pages (AMP) can be abused to bypass phishing protections by presenting a trustworthy domain with containing a redirect.

The lure URL can be embedded into the Google AMP URL like this:

```https://www.google.com/amp/s/``` / ```phish_url``` or ```https://www.google.co.uk/amp/s/``` / ```phish_url```


---

## Manipulate "Display Name" for Outlook

The "display name" field in the email can be used to manipulate to "from email" field off the screen.

This is working in Outlook desktop and OWA as of 08/08/23

Because the "display name" and "from email" are in the same visual element, the "from email" can be manipulated by pushing it out of the displayed element using non-visable Unicode characters.

For example:

```
Your Manager\s\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\sTo:⠀colleague1⠀<colleague1@company.com>;⠀colleague2⠀<colleague2@company.com>;⠀colleague3⠀<colleague3@company.com>;⠀colleague4⠀<colleague4@company.com>;⠀colleague5⠀<colleague5@company.com>;⠀colleague6⠀<personal.mail1@outlook.com>;⠀colleague7>
```

or

```
Your Manager <your.manager@company.com>⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀To:⠀colleague1⠀<colleague1@company.com>;⠀colleague2⠀<colleague2@company.com>;⠀colleague3⠀<colleague3@company.com>;⠀colleague4⠀<colleague4@company.com>;⠀colleague5⠀<colleague5@company.com>;⠀colleague6⠀<personal.mail1@outlook.com>;⠀colleague7
```

Would display similar to this:

![Screenshot 2023-08-08 234239](https://github.com/aalex954/evilginx2-tuned/assets/6628565/a88127e3-04fa-4a0a-8257-938e7736fbd7)

Some possible characters:

- Space (U+0020)
- No-Break Space (U+00A0)
- Ogham Space Mark (U+1680)
- Mongolian Vowel Separator (U+180E)
- En Quad (U+2000)
- Em Quad (U+2001)
- En Space (U+2002)
- Em Space (U+2003)
- Three-Per-Em Space (U+2004)
- Four-Per-Em Space (U+2005)
- Six-Per-Em Space (U+2006)
- Figure Space (U+2007)
- Punctuation Space (U+2008)
- Thin Space (U+2009)
- Hair Space (U+200A)
- Zero Width Space (U+200B)
- Zero Width Non-Joiner (U+200C)
- Zero Width Joiner (U+200D)
- Line Separator (U+2028)
- Paragraph Separator (U+2029)
- Narrow No-Break Space (U+202F)
- Medium Mathematical Space (U+205F)
- Ideographic Space (U+3000)
- Braille Pattern Blank (U+2800)

Regex pattern: ```[\u0020\u00A0\u1680\u180E\u2000-\u200A\u200B-\u200D\u2028-\u2029\u202F\u205F\u3000\u2800]```


All credit goes to: https://gitlab.com/email_bug/outlook_email_auth_bypass


### Detection

To counter this, a regex pattern can be used:

```(\w+\s)+[\u0020\u00A0\u1680\u180E\u2000-\u200A\u200B-\u200D\u2028-\u2029\u202F\u205F\u3000\u2800]+\sTo:\w+<\w+@\w+\.\w+>```

This regex should match a string with any number of words followed by a sequence of blank-appearing characters, then the "To:" string, and an email.

or more generically

```(\w+\s)+[\u0020\u00A0\u1680\u180E\u2000-\u200A\u200B-\u200D\u2028-\u2029\u202F\u205F\u3000\u2800]+.*```

This pattern now matches any number of words followed by a sequence of blank-appearing characters and then any sequence of characters afterward.

![Screenshot 2023-08-08 235841](https://github.com/aalex954/evilginx2-tuned/assets/6628565/68be4518-b1d5-476c-9c0b-ce7a0aa1a255)

---
# Go JOSE 

[![godoc](http://img.shields.io/badge/godoc-version_1-blue.svg?style=flat)](https://godoc.org/gopkg.in/square/go-jose.v1)
[![godoc](http://img.shields.io/badge/godoc-version_2-blue.svg?style=flat)](https://godoc.org/gopkg.in/square/go-jose.v2)
[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/go-jose/master/LICENSE)
[![build](https://travis-ci.org/square/go-jose.svg?branch=v2)](https://travis-ci.org/square/go-jose)
[![coverage](https://coveralls.io/repos/github/square/go-jose/badge.svg?branch=v2)](https://coveralls.io/r/square/go-jose)

Package jose aims to provide an implementation of the Javascript Object Signing
and Encryption set of standards. This includes support for JSON Web Encryption,
JSON Web Signature, and JSON Web Token standards.

**Disclaimer**: This library contains encryption software that is subject to
the U.S. Export Administration Regulations. You may not export, re-export,
transfer or download this code or any part of it in violation of any United
States law, directive or regulation. In particular this software may not be
exported or re-exported in any form or on any media to Iran, North Sudan,
Syria, Cuba, or North Korea, or to denied persons or entities mentioned on any
US maintained blocked list.

## Overview

The implementation follows the
[JSON Web Encryption](http://dx.doi.org/10.17487/RFC7516) (RFC 7516),
[JSON Web Signature](http://dx.doi.org/10.17487/RFC7515) (RFC 7515), and
[JSON Web Token](http://dx.doi.org/10.17487/RFC7519) (RFC 7519).
Tables of supported algorithms are shown below. The library supports both
the compact and full serialization formats, and has optional support for
multiple recipients. It also comes with a small command-line utility
([`jose-util`](https://github.com/square/go-jose/tree/v2/jose-util))
for dealing with JOSE messages in a shell.

**Note**: We use a forked version of the `encoding/json` package from the Go
standard library which uses case-sensitive matching for member names (instead
of [case-insensitive matching](https://www.ietf.org/mail-archive/web/json/current/msg03763.html)).
This is to avoid differences in interpretation of messages between go-jose and
libraries in other languages.

### Versions

We use [gopkg.in](https://gopkg.in) for versioning.

[Version 2](https://gopkg.in/square/go-jose.v2)
([branch](https://github.com/square/go-jose/tree/v2),
[doc](https://godoc.org/gopkg.in/square/go-jose.v2)) is the current version:

    import "gopkg.in/square/go-jose.v2"

The old `v1` branch ([go-jose.v1](https://gopkg.in/square/go-jose.v1)) will
still receive backported bug fixes and security fixes, but otherwise
development is frozen. All new feature development takes place on the `v2`
branch. Version 2 also contains additional sub-packages such as the
[jwt](https://godoc.org/gopkg.in/square/go-jose.v2/jwt) implementation
contributed by [@shaxbee](https://github.com/shaxbee).

### Supported algorithms

See below for a table of supported algorithms. Algorithm identifiers match
the names in the [JSON Web Algorithms](http://dx.doi.org/10.17487/RFC7518)
standard where possible. The Godoc reference has a list of constants.

 Key encryption             | Algorithm identifier(s)
 :------------------------- | :------------------------------
 RSA-PKCS#1v1.5             | RSA1_5
 RSA-OAEP                   | RSA-OAEP, RSA-OAEP-256
 AES key wrap               | A128KW, A192KW, A256KW
 AES-GCM key wrap           | A128GCMKW, A192GCMKW, A256GCMKW
 ECDH-ES + AES key wrap     | ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
 ECDH-ES (direct)           | ECDH-ES<sup>1</sup>
 Direct encryption          | dir<sup>1</sup>

<sup>1. Not supported in multi-recipient mode</sup>

 Signing / MAC              | Algorithm identifier(s)
 :------------------------- | :------------------------------
 RSASSA-PKCS#1v1.5          | RS256, RS384, RS512
 RSASSA-PSS                 | PS256, PS384, PS512
 HMAC                       | HS256, HS384, HS512
 ECDSA                      | ES256, ES384, ES512
 Ed25519                    | EdDSA<sup>2</sup>

<sup>2. Only available in version 2 of the package</sup>

 Content encryption         | Algorithm identifier(s)
 :------------------------- | :------------------------------
 AES-CBC+HMAC               | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
 AES-GCM                    | A128GCM, A192GCM, A256GCM 

 Compression                | Algorithm identifiers(s)
 :------------------------- | -------------------------------
 DEFLATE (RFC 1951)         | DEF

### Supported key types

See below for a table of supported key types. These are understood by the
library, and can be passed to corresponding functions such as `NewEncrypter` or
`NewSigner`. Each of these keys can also be wrapped in a JWK if desired, which
allows attaching a key id.

 Algorithm(s)               | Corresponding types
 :------------------------- | -------------------------------
 RSA                        | *[rsa.PublicKey](http://golang.org/pkg/crypto/rsa/#PublicKey), *[rsa.PrivateKey](http://golang.org/pkg/crypto/rsa/#PrivateKey)
 ECDH, ECDSA                | *[ecdsa.PublicKey](http://golang.org/pkg/crypto/ecdsa/#PublicKey), *[ecdsa.PrivateKey](http://golang.org/pkg/crypto/ecdsa/#PrivateKey)
 EdDSA<sup>1</sup>          | [ed25519.PublicKey](https://godoc.org/golang.org/x/crypto/ed25519#PublicKey), [ed25519.PrivateKey](https://godoc.org/golang.org/x/crypto/ed25519#PrivateKey)
 AES, HMAC                  | []byte

<sup>1. Only available in version 2 of the package</sup>

## Examples

[![godoc](http://img.shields.io/badge/godoc-version_1-blue.svg?style=flat)](https://godoc.org/gopkg.in/square/go-jose.v1)
[![godoc](http://img.shields.io/badge/godoc-version_2-blue.svg?style=flat)](https://godoc.org/gopkg.in/square/go-jose.v2)

Examples can be found in the Godoc
reference for this package. The
[`jose-util`](https://github.com/square/go-jose/tree/v2/jose-util)
subdirectory also contains a small command-line utility which might be useful
as an example.
# Safe JSON

This repository contains a fork of the `encoding/json` package from Go 1.6.

The following changes were made:

* Object deserialization uses case-sensitive member name matching instead of
  [case-insensitive matching](https://www.ietf.org/mail-archive/web/json/current/msg03763.html).
  This is to avoid differences in the interpretation of JOSE messages between
  go-jose and libraries written in other languages.
* When deserializing a JSON object, we check for duplicate keys and reject the
  input whenever we detect a duplicate. Rather than trying to work with malformed
  data, we prefer to reject it right away.
# YAML support for the Go language

Introduction
------------

The yaml package enables Go programs to comfortably encode and decode YAML
values. It was developed within [Canonical](https://www.canonical.com) as
part of the [juju](https://juju.ubuntu.com) project, and is based on a
pure Go port of the well-known [libyaml](http://pyyaml.org/wiki/LibYAML)
C library to parse and generate YAML data quickly and reliably.

Compatibility
-------------

The yaml package supports most of YAML 1.1 and 1.2, including support for
anchors, tags, map merging, etc. Multi-document unmarshalling is not yet
implemented, and base-60 floats from YAML 1.1 are purposefully not
supported since they're a poor design and are gone in YAML 1.2.

Installation and usage
----------------------

The import path for the package is *gopkg.in/yaml.v2*.

To install it, run:

    go get gopkg.in/yaml.v2

API documentation
-----------------

If opened in a browser, the import path itself leads to the API documentation:

  * [https://gopkg.in/yaml.v2](https://gopkg.in/yaml.v2)

API stability
-------------

The package API for yaml v2 will remain stable as described in [gopkg.in](https://gopkg.in).


License
-------

The yaml package is licensed under the Apache License 2.0. Please see the LICENSE file for details.


Example
-------

```Go
package main

import (
        "fmt"
        "log"

        "gopkg.in/yaml.v2"
)

var data = `
a: Easy!
b:
  c: 2
  d: [3, 4]
`

// Note: struct fields must be public in order for unmarshal to
// correctly populate the data.
type T struct {
        A string
        B struct {
                RenamedC int   `yaml:"c"`
                D        []int `yaml:",flow"`
        }
}

func main() {
        t := T{}
    
        err := yaml.Unmarshal([]byte(data), &t)
        if err != nil {
                log.Fatalf("error: %v", err)
        }
        fmt.Printf("--- t:\n%v\n\n", t)
    
        d, err := yaml.Marshal(&t)
        if err != nil {
                log.Fatalf("error: %v", err)
        }
        fmt.Printf("--- t dump:\n%s\n\n", string(d))
    
        m := make(map[interface{}]interface{})
    
        err = yaml.Unmarshal([]byte(data), &m)
        if err != nil {
                log.Fatalf("error: %v", err)
        }
        fmt.Printf("--- m:\n%v\n\n", m)
    
        d, err = yaml.Marshal(&m)
        if err != nil {
                log.Fatalf("error: %v", err)
        }
        fmt.Printf("--- m dump:\n%s\n\n", string(d))
}
```

This example will generate the following output:

```
--- t:
{Easy! {2 [3 4]}}

--- t dump:
a: Easy!
b:
  c: 2
  d: [3, 4]


--- m:
map[a:Easy! b:map[c:2 d:[3 4]]]

--- m dump:
a: Easy!
b:
  c: 2
  d:
  - 3
  - 4
```

# tinyqueue
<a href="https://godoc.org/github.com/tidwall/tinyqueue"><img src="https://img.shields.io/badge/api-reference-blue.svg?style=flat-square" alt="GoDoc"></a>

tinyqueue is a Go package for binary heap priority queues.
Ported from the [tinyqueue](https://github.com/mourner/tinyqueue) Javascript library.


RTree implementation for Go
===========================

[![Build Status](https://travis-ci.org/tidwall/rtree.svg?branch=master)](https://travis-ci.org/tidwall/rtree)
[![GoDoc](https://godoc.org/github.com/tidwall/rtree?status.svg)](https://godoc.org/github.com/tidwall/rtree)

This package provides an in-memory R-Tree implementation for Go, useful as a spatial data structure.
It has support for 1-20 dimensions, and can store and search multidimensions interchangably in the same tree.

Authors
-------
* 1983 Original algorithm and test code by Antonin Guttman and Michael Stonebraker, UC Berkely
* 1994 ANCI C ported from original test code by Melinda Green 
* 1995 Sphere volume fix for degeneracy problem submitted by Paul Brook
* 2004 Templated C++ port by Greg Douglas
* 2016 Go port by Josh Baker
* 2018 Added kNN and merged in some of the RBush logic by Vladimir Agafonkin

License
-------
RTree source code is available under the MIT License.

BTree implementation for Go
===========================

![Travis CI Build Status](https://api.travis-ci.org/tidwall/btree.svg?branch=master)
[![GoDoc](https://godoc.org/github.com/tidwall/btree?status.svg)](https://godoc.org/github.com/tidwall/btree)

This package provides an in-memory B-Tree implementation for Go, useful as
an ordered, mutable data structure.

This is a fork of the wonderful [google/btree](https://github.com/google/btree) package. It's has all the same great features and adds a few more.

- Descend* functions for iterating backwards.
- Iteration performance boost.
- User defined context.

User defined context
--------------------
This is a great new feature that allows for entering the same item into multiple B-trees, and each B-tree have a different ordering formula.

For example:

```go
package main

import (
	"fmt"

	"github.com/tidwall/btree"
)

type Item struct {
	Key, Val string
}

func (i1 *Item) Less(item btree.Item, ctx interface{}) bool {
	i2 := item.(*Item)
	switch tag := ctx.(type) {
	case string:
		if tag == "vals" {
			if i1.Val < i2.Val {
				return true
			} else if i1.Val > i2.Val {
				return false
			}
			// Both vals are equal so we should fall though
			// and let the key comparison take over.
		}
	}
	return i1.Key < i2.Key
}

func main() {

	// Create a tree for keys and a tree for values.
	// The "keys" tree will be sorted on the Keys field.
	// The "values" tree will be sorted on the Values field.
	keys := btree.New(16, "keys")
	vals := btree.New(16, "vals")

	// Create some items.
	users := []*Item{
		&Item{Key: "user:1", Val: "Jane"},
		&Item{Key: "user:2", Val: "Andy"},
		&Item{Key: "user:3", Val: "Steve"},
		&Item{Key: "user:4", Val: "Andrea"},
		&Item{Key: "user:5", Val: "Janet"},
		&Item{Key: "user:6", Val: "Andy"},
	}

	// Insert each user into both trees
	for _, user := range users {
		keys.ReplaceOrInsert(user)
		vals.ReplaceOrInsert(user)
	}

	// Iterate over each user in the key tree
	keys.Ascend(func(item btree.Item) bool {
		kvi := item.(*Item)
		fmt.Printf("%s %s\n", kvi.Key, kvi.Val)
		return true
	})

	fmt.Printf("\n")
	// Iterate over each user in the val tree
	vals.Ascend(func(item btree.Item) bool {
		kvi := item.(*Item)
		fmt.Printf("%s %s\n", kvi.Key, kvi.Val)
		return true
	})
}

// Should see the results
/*
user:1 Jane
user:2 Andy
user:3 Steve
user:4 Andrea
user:5 Janet
user:6 Andy

user:4 Andrea
user:2 Andy
user:6 Andy
user:1 Jane
user:3 Steve
*/
```
<p align="center">
<img
    src="logo.png"
    width="307" height="150" border="0" alt="BuntDB">
<br>
<a href="https://travis-ci.org/tidwall/buntdb"><img src="https://img.shields.io/travis/tidwall/buntdb.svg?style=flat-square" alt="Build Status"></a>
<a href="http://gocover.io/github.com/tidwall/buntdb"><img src="https://img.shields.io/badge/coverage-95%25-brightgreen.svg?style=flat-square" alt="Code Coverage"></a>
<a href="https://goreportcard.com/report/github.com/tidwall/buntdb"><img src="https://goreportcard.com/badge/github.com/tidwall/buntdb?style=flat-square" alt="Go Report Card"></a>
<a href="https://godoc.org/github.com/tidwall/buntdb"><img src="https://img.shields.io/badge/api-reference-blue.svg?style=flat-square" alt="GoDoc"></a>
</p>

BuntDB is a low-level, in-memory, key/value store in pure Go.
It persists to disk, is ACID compliant, and uses locking for multiple
readers and a single writer. It supports custom indexes and geospatial
data. It's ideal for projects that need a dependable database and favor
speed over data size.

Features
========

- In-memory database for [fast reads and writes](#performance)
- Embeddable with a [simple API](https://godoc.org/github.com/tidwall/buntdb)
- [Spatial indexing](#spatial-indexes) for up to 20 dimensions; Useful for Geospatial data
- Index fields inside [JSON](#json-indexes) documents
- [Collate i18n Indexes](#collate-i18n-indexes) using the optional [collate package](https://github.com/tidwall/collate)
- Create [custom indexes](#custom-indexes) for any data type
- Support for [multi value indexes](#multi-value-index); Similar to a SQL multi column index
- [Built-in types](#built-in-types) that are easy to get up & running; String, Uint, Int, Float
- Flexible [iteration](#iterating) of data; ascending, descending, and ranges
- [Durable append-only file](#append-only-file) format for persistence
- Option to evict old items with an [expiration](#data-expiration) TTL
- Tight codebase, under 2K loc using the `cloc` command
- ACID semantics with locking [transactions](#transactions) that support rollbacks


Getting Started
===============

## Installing

To start using BuntDB, install Go and run `go get`:

```sh
$ go get -u github.com/tidwall/buntdb
```

This will retrieve the library.


## Opening a database

The primary object in BuntDB is a `DB`. To open or create your
database, use the `buntdb.Open()` function:

```go
package main

import (
	"log"

	"github.com/tidwall/buntdb"
)

func main() {
	// Open the data.db file. It will be created if it doesn't exist.
	db, err := buntdb.Open("data.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	...
}
```

It's also possible to open a database that does not persist to disk by using `:memory:` as the path of the file.

```go
buntdb.Open(":memory:") // Open a file that does not persist to disk.
```

## Transactions
All reads and writes must be performed from inside a transaction. BuntDB can have one write transaction opened at a time, but can have many concurrent read transactions. Each transaction maintains a stable view of the database. In other words, once a transaction has begun, the data for that transaction cannot be changed by other transactions.

Transactions run in a function that exposes a `Tx` object, which represents the transaction state. While inside a transaction, all database operations should be performed using this object. You should never access the origin `DB` object while inside a transaction. Doing so may have side-effects, such as blocking your application.

When a transaction fails, it will roll back, and revert all changes that occurred to the database during that transaction. There's a single return value that you can use to close the transaction. For read/write transactions, returning an error this way will force the transaction to roll back. When a read/write transaction succeeds all changes are persisted to disk.

### Read-only Transactions
A read-only transaction should be used when you don't need to make changes to the data. The advantage of a read-only transaction is that there can be many running concurrently.

```go
err := db.View(func(tx *buntdb.Tx) error {
	...
	return nil
})
```

### Read/write Transactions
A read/write transaction is used when you need to make changes to your data. There can only be one read/write transaction running at a time. So make sure you close it as soon as you are done with it.

```go
err := db.Update(func(tx *buntdb.Tx) error {
	...
	return nil
})
```

## Setting and getting key/values

To set a value you must open a read/write transaction:

```go
err := db.Update(func(tx *buntdb.Tx) error {
	_, _, err := tx.Set("mykey", "myvalue", nil)
	return err
})
```


To get the value:

```go
err := db.View(func(tx *buntdb.Tx) error {
	val, err := tx.Get("mykey")
	if err != nil{
		return err
	}
	fmt.Printf("value is %s\n", val)
	return nil
})
```

Getting non-existent values will cause an `ErrNotFound` error.

### Iterating
All keys/value pairs are ordered in the database by the key. To iterate over the keys:

```go
err := db.View(func(tx *buntdb.Tx) error {
	err := tx.Ascend("", func(key, value string) bool {
		fmt.Printf("key: %s, value: %s\n", key, value)
	})
	return err
})
```

There is also `AscendGreaterOrEqual`, `AscendLessThan`, `AscendRange`, `AscendEqual`, `Descend`, `DescendLessOrEqual`, `DescendGreaterThan`, `DescendRange`, and `DescendEqual`. Please see the [documentation](https://godoc.org/github.com/tidwall/buntdb) for more information on these functions.


## Custom Indexes
Initially all data is stored in a single [B-tree](https://en.wikipedia.org/wiki/B-tree) with each item having one key and one value. All of these items are ordered by the key. This is great for quickly getting a value from a key or [iterating](#iterating) over the keys. Feel free to peruse the [B-tree implementation](https://github.com/tidwall/btree).

You can also create custom indexes that allow for ordering and [iterating](#iterating) over values. A custom index also uses a B-tree, but it's more flexible because it allows for custom ordering.

For example, let's say you want to create an index for ordering names:

```go
db.CreateIndex("names", "*", buntdb.IndexString)
```

This will create an index named `names` which stores and sorts all values. The second parameter is a pattern that is used to filter on keys. A `*` wildcard argument means that we want to accept all keys. `IndexString` is a built-in function that performs case-insensitive ordering on the values

Now you can add various names:

```go
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("user:0:name", "tom", nil)
	tx.Set("user:1:name", "Randi", nil)
	tx.Set("user:2:name", "jane", nil)
	tx.Set("user:4:name", "Janet", nil)
	tx.Set("user:5:name", "Paula", nil)
	tx.Set("user:6:name", "peter", nil)
	tx.Set("user:7:name", "Terri", nil)
	return nil
})
```

Finally you can iterate over the index:

```go
db.View(func(tx *buntdb.Tx) error {
	tx.Ascend("names", func(key, val string) bool {
	fmt.Printf(buf, "%s %s\n", key, val)
		return true
	})
	return nil
})
```
The output should be:
```
user:2:name jane
user:4:name Janet
user:5:name Paula
user:6:name peter
user:1:name Randi
user:7:name Terri
user:0:name tom
```

The pattern parameter can be used to filter on keys like this:

```go
db.CreateIndex("names", "user:*", buntdb.IndexString)
```

Now only items with keys that have the prefix `user:` will be added to the `names` index.


### Built-in types
Along with `IndexString`, there is also `IndexInt`, `IndexUint`, and `IndexFloat`.
These are built-in types for indexing. You can choose to use these or create your own.

So to create an index that is numerically ordered on an age key, we could use:

```go
db.CreateIndex("ages", "user:*:age", buntdb.IndexInt)
```

And then add values:

```go
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("user:0:age", "35", nil)
	tx.Set("user:1:age", "49", nil)
	tx.Set("user:2:age", "13", nil)
	tx.Set("user:4:age", "63", nil)
	tx.Set("user:5:age", "8", nil)
	tx.Set("user:6:age", "3", nil)
	tx.Set("user:7:age", "16", nil)
	return nil
})
```

```go
db.View(func(tx *buntdb.Tx) error {
	tx.Ascend("ages", func(key, val string) bool {
	fmt.Printf(buf, "%s %s\n", key, val)
		return true
	})
	return nil
})
```

The output should be:
```
user:6:age 3
user:5:age 8
user:2:age 13
user:7:age 16
user:0:age 35
user:1:age 49
user:4:age 63
```

## Spatial Indexes
BuntDB has support for spatial indexes by storing rectangles in an [R-tree](https://en.wikipedia.org/wiki/R-tree). An R-tree is organized in a similar manner as a [B-tree](https://en.wikipedia.org/wiki/B-tree), and both are balanced trees. But, an R-tree is special because it can operate on data that is in multiple dimensions. This is super handy for Geospatial applications.

To create a spatial index use the `CreateSpatialIndex` function:

```go
db.CreateSpatialIndex("fleet", "fleet:*:pos", buntdb.IndexRect)
```

Then `IndexRect` is a built-in function that converts rect strings to a format that the R-tree can use. It's easy to use this function out of the box, but you might find it better to create a custom one that renders from a different format, such as [Well-known text](https://en.wikipedia.org/wiki/Well-known_text) or [GeoJSON](http://geojson.org/).

To add some lon,lat points to the `fleet` index:

```go
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("fleet:0:pos", "[-115.567 33.532]", nil)
	tx.Set("fleet:1:pos", "[-116.671 35.735]", nil)
	tx.Set("fleet:2:pos", "[-113.902 31.234]", nil)
	return nil
})
```

And then you can run the `Intersects` function on the index:

```go
db.View(func(tx *buntdb.Tx) error {
	tx.Intersects("fleet", "[-117 30],[-112 36]", func(key, val string) bool {
		...
		return true
	})
	return nil
})
```

This will get all three positions.

### k-Nearest Neighbors

Use the `Nearby` function to get all the positions in order of nearest to farthest :

```go
db.View(func(tx *buntdb.Tx) error {
	tx.Nearby("fleet", "[-113 33]", func(key, val string, dist float64) bool {
		...
		return true
	})
	return nil
})
```

### Spatial bracket syntax

The bracket syntax `[-117 30],[-112 36]` is unique to BuntDB, and it's how the built-in rectangles are processed. But, you are not limited to this syntax. Whatever Rect function you choose to use during `CreateSpatialIndex` will be used to process the parameter, in this case it's `IndexRect`.

- **2D rectangle:** `[10 15],[20 25]`
*Min XY: "10x15", Max XY: "20x25"*

- **3D rectangle:** `[10 15 12],[20 25 18]`
*Min XYZ: "10x15x12", Max XYZ: "20x25x18"*

- **2D point:** `[10 15]`
*XY: "10x15"*

- **LonLat point:** `[-112.2693 33.5123]`
*LatLon: "33.5123 -112.2693"*

- **LonLat bounding box:** `[-112.26 33.51],[-112.18 33.67]`
*Min LatLon: "33.51 -112.26", Max LatLon: "33.67 -112.18"*

**Notice:** The longitude is the Y axis and is on the left, and latitude is the X axis and is on the right.

You can also represent `Infinity` by using `-inf` and `+inf`.
For example, you might have the following points (`[X Y M]` where XY is a point and M is a timestamp):
```
[3 9 1]
[3 8 2]
[4 8 3]
[4 7 4]
[5 7 5]
[5 6 6]
```

You can then do a search for all points with `M` between 2-4 by calling `Intersects`.

```go
tx.Intersects("points", "[-inf -inf 2],[+inf +inf 4]", func(key, val string) bool {
	println(val)
	return true
})
```

Which will return:

```
[3 8 2]
[4 8 3]
[4 7 4]
```

## JSON Indexes
Indexes can be created on individual fields inside JSON documents. BuntDB uses [GJSON](https://github.com/tidwall/gjson) under the hood.

For example:

```go
package main

import (
	"fmt"

	"github.com/tidwall/buntdb"
)

func main() {
	db, _ := buntdb.Open(":memory:")
	db.CreateIndex("last_name", "*", buntdb.IndexJSON("name.last"))
	db.CreateIndex("age", "*", buntdb.IndexJSON("age"))
	db.Update(func(tx *buntdb.Tx) error {
		tx.Set("1", `{"name":{"first":"Tom","last":"Johnson"},"age":38}`, nil)
		tx.Set("2", `{"name":{"first":"Janet","last":"Prichard"},"age":47}`, nil)
		tx.Set("3", `{"name":{"first":"Carol","last":"Anderson"},"age":52}`, nil)
		tx.Set("4", `{"name":{"first":"Alan","last":"Cooper"},"age":28}`, nil)
		return nil
	})
	db.View(func(tx *buntdb.Tx) error {
		fmt.Println("Order by last name")
		tx.Ascend("last_name", func(key, value string) bool {
			fmt.Printf("%s: %s\n", key, value)
			return true
		})
		fmt.Println("Order by age")
		tx.Ascend("age", func(key, value string) bool {
			fmt.Printf("%s: %s\n", key, value)
			return true
		})
		fmt.Println("Order by age range 30-50")
		tx.AscendRange("age", `{"age":30}`, `{"age":50}`, func(key, value string) bool {
			fmt.Printf("%s: %s\n", key, value)
			return true
		})
		return nil
	})
}
```

Results:

```
Order by last name
3: {"name":{"first":"Carol","last":"Anderson"},"age":52}
4: {"name":{"first":"Alan","last":"Cooper"},"age":28}
1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
2: {"name":{"first":"Janet","last":"Prichard"},"age":47}

Order by age
4: {"name":{"first":"Alan","last":"Cooper"},"age":28}
1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
2: {"name":{"first":"Janet","last":"Prichard"},"age":47}
3: {"name":{"first":"Carol","last":"Anderson"},"age":52}

Order by age range 30-50
1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
2: {"name":{"first":"Janet","last":"Prichard"},"age":47}
```

## Multi Value Index
With BuntDB it's possible to join multiple values on a single index.
This is similar to a [multi column index](http://dev.mysql.com/doc/refman/5.7/en/multiple-column-indexes.html) in a traditional SQL database.

In this example we are creating a multi value index on "name.last" and "age":

```go
db, _ := buntdb.Open(":memory:")
db.CreateIndex("last_name_age", "*", buntdb.IndexJSON("name.last"), buntdb.IndexJSON("age"))
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("1", `{"name":{"first":"Tom","last":"Johnson"},"age":38}`, nil)
	tx.Set("2", `{"name":{"first":"Janet","last":"Prichard"},"age":47}`, nil)
	tx.Set("3", `{"name":{"first":"Carol","last":"Anderson"},"age":52}`, nil)
	tx.Set("4", `{"name":{"first":"Alan","last":"Cooper"},"age":28}`, nil)
	tx.Set("5", `{"name":{"first":"Sam","last":"Anderson"},"age":51}`, nil)
	tx.Set("6", `{"name":{"first":"Melinda","last":"Prichard"},"age":44}`, nil)
	return nil
})
db.View(func(tx *buntdb.Tx) error {
	tx.Ascend("last_name_age", func(key, value string) bool {
		fmt.Printf("%s: %s\n", key, value)
		return true
	})
	return nil
})

// Output:
// 5: {"name":{"first":"Sam","last":"Anderson"},"age":51}
// 3: {"name":{"first":"Carol","last":"Anderson"},"age":52}
// 4: {"name":{"first":"Alan","last":"Cooper"},"age":28}
// 1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
// 6: {"name":{"first":"Melinda","last":"Prichard"},"age":44}
// 2: {"name":{"first":"Janet","last":"Prichard"},"age":47}
```

## Descending Ordered Index
Any index can be put in descending order by wrapping it's less function with `buntdb.Desc`.

```go
db.CreateIndex("last_name_age", "*",
buntdb.IndexJSON("name.last"),
buntdb.Desc(buntdb.IndexJSON("age")))
```

This will create a multi value index where the last name is ascending and the age is descending.

## Collate i18n Indexes

Using the external [collate package](https://github.com/tidwall/collate) it's possible to create
indexes that are sorted by the specified language. This is similar to the [SQL COLLATE keyword](https://msdn.microsoft.com/en-us/library/ms174596.aspx) found in traditional databases.

To install:

```
go get -u github.com/tidwall/collate
```

For example:

```go
import "github.com/tidwall/collate"

// To sort case-insensitive in French.
db.CreateIndex("name", "*", collate.IndexString("FRENCH_CI"))

// To specify that numbers should sort numerically ("2" < "12")
// and use a comma to represent a decimal point.
db.CreateIndex("amount", "*", collate.IndexString("FRENCH_NUM"))
```

There's also support for Collation on JSON indexes:

```go
db.CreateIndex("last_name", "*", collate.IndexJSON("CHINESE_CI", "name.last"))
```

Check out the [collate project](https://github.com/tidwall/collate) for more information.

## Data Expiration
Items can be automatically evicted by using the `SetOptions` object in the `Set` function to set a `TTL`.

```go
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("mykey", "myval", &buntdb.SetOptions{Expires:true, TTL:time.Second})
	return nil
})
```

Now `mykey` will automatically be deleted after one second. You can remove the TTL by setting the value again with the same key/value, but with the options parameter set to nil.

## Delete while iterating
BuntDB does not currently support deleting a key while in the process of iterating.
As a workaround you'll need to delete keys following the completion of the iterator.

```go
var delkeys []string
tx.AscendKeys("object:*", func(k, v string) bool {
	if someCondition(k) == true {
		delkeys = append(delkeys, k)
	}
	return true // continue
})
for _, k := range delkeys {
	if _, err = tx.Delete(k); err != nil {
		return err
	}
}
```

## Append-only File

BuntDB uses an AOF (append-only file) which is a log of all database changes that occur from operations like `Set()` and `Delete()`.

The format of this file looks like:
```
set key:1 value1
set key:2 value2
set key:1 value3
del key:2
...
```

When the database opens again, it will read back the aof file and process each command in exact order.
This read process happens one time when the database opens.
From there on the file is only appended.

As you may guess this log file can grow large over time.
There's a background routine that automatically shrinks the log file when it gets too large.
There is also a `Shrink()` function which will rewrite the aof file so that it contains only the items in the database.
The shrink operation does not lock up the database so read and write transactions can continue while shrinking is in process.

### Durability and fsync

By default BuntDB executes an `fsync` once every second on the [aof file](#append-only-file). Which simply means that there's a chance that up to one second of data might be lost. If you need higher durability then there's an optional database config setting `Config.SyncPolicy` which can be set to `Always`.

The `Config.SyncPolicy` has the following options:

- `Never` - fsync is managed by the operating system, less safe
- `EverySecond` - fsync every second, fast and safer, this is the default
- `Always` - fsync after every write, very durable, slower

## Config

Here are some configuration options that can be use to change various behaviors of the database.

- **SyncPolicy** adjusts how often the data is synced to disk. This value can be Never, EverySecond, or Always. Default is EverySecond.
- **AutoShrinkPercentage** is used by the background process to trigger a shrink of the aof file when the size of the file is larger than the percentage of the result of the previous shrunk file. For example, if this value is 100, and the last shrink process resulted in a 100mb file, then the new aof file must be 200mb before a shrink is triggered. Default is 100.
- **AutoShrinkMinSize** defines the minimum size of the aof file before an automatic shrink can occur. Default is 32MB.
- **AutoShrinkDisabled** turns off automatic background shrinking. Default is false.

To update the configuration you should call `ReadConfig` followed by `SetConfig`. For example:

```go

var config buntdb.Config
if err := db.ReadConfig(&config); err != nil{
	log.Fatal(err)
}
if err := db.WriteConfig(config); err != nil{
	log.Fatal(err)
}
```

## Performance

How fast is BuntDB?

Here are some example [benchmarks](https://github.com/tidwall/raft-buntdb#raftstore-performance-comparison) when using BuntDB in a Raft Store implementation.

You can also run the standard Go benchmark tool from the project root directory:

```
go test --bench=.
```

### BuntDB-Benchmark

There's a [custom utility](https://github.com/tidwall/buntdb-benchmark) that was created specifically for benchmarking BuntDB.

*These are the results from running the benchmarks on a MacBook Pro 15" 2.8 GHz Intel Core i7:*

```
$ buntdb-benchmark -q
GET: 4609604.74 operations per second
SET: 248500.33 operations per second
ASCEND_100: 2268998.79 operations per second
ASCEND_200: 1178388.14 operations per second
ASCEND_400: 679134.20 operations per second
ASCEND_800: 348445.55 operations per second
DESCEND_100: 2313821.69 operations per second
DESCEND_200: 1292738.38 operations per second
DESCEND_400: 675258.76 operations per second
DESCEND_800: 337481.67 operations per second
SPATIAL_SET: 134824.60 operations per second
SPATIAL_INTERSECTS_100: 939491.47 operations per second
SPATIAL_INTERSECTS_200: 561590.40 operations per second
SPATIAL_INTERSECTS_400: 306951.15 operations per second
SPATIAL_INTERSECTS_800: 159673.91 operations per second
```

To install this utility:

```
go get github.com/tidwall/buntdb-benchmark
```



## Contact
Josh Baker [@tidwall](http://twitter.com/tidwall)

## License

BuntDB source code is available under the MIT [License](/LICENSE).
Match
=====
<a href="https://travis-ci.org/tidwall/match"><img src="https://img.shields.io/travis/tidwall/match.svg?style=flat-square" alt="Build Status"></a>
<a href="https://godoc.org/github.com/tidwall/match"><img src="https://img.shields.io/badge/api-reference-blue.svg?style=flat-square" alt="GoDoc"></a>

Match is a very simple pattern matcher where '*' matches on any 
number characters and '?' matches on any one character.

Installing
----------

```
go get -u github.com/tidwall/match
```

Example
-------

```go
match.Match("hello", "*llo") 
match.Match("jello", "?ello") 
match.Match("hello", "h*o") 
```


Contact
-------
Josh Baker [@tidwall](http://twitter.com/tidwall)

License
-------
Redcon source code is available under the MIT [License](/LICENSE).
# Pretty
[![Build Status](https://img.shields.io/travis/tidwall/pretty.svg?style=flat-square)](https://travis-ci.org/tidwall/prettty)
[![Coverage Status](https://img.shields.io/badge/coverage-100%25-brightgreen.svg?style=flat-square)](http://gocover.io/github.com/tidwall/pretty)
[![GoDoc](https://img.shields.io/badge/api-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/tidwall/pretty) 


Pretty is a Go package that provides [fast](#performance) methods for formatting JSON for human readability, or to compact JSON for smaller payloads.

Getting Started
===============

## Installing

To start using Pretty, install Go and run `go get`:

```sh
$ go get -u github.com/tidwall/pretty
```

This will retrieve the library.

## Pretty

Using this example:

```json
{"name":  {"first":"Tom","last":"Anderson"},  "age":37,
"children": ["Sara","Alex","Jack"],
"fav.movie": "Deer Hunter", "friends": [
    {"first": "Janet", "last": "Murphy", "age": 44}
  ]}
```

The following code:
```go
result = pretty.Pretty(example)
```

Will format the json to:

```json
{
  "name": {
    "first": "Tom",
    "last": "Anderson"
  },
  "age": 37,
  "children": ["Sara", "Alex", "Jack"],
  "fav.movie": "Deer Hunter",
  "friends": [
    {
      "first": "Janet",
      "last": "Murphy",
      "age": 44
    }
  ]
}
```

## Color

Color will colorize the json for outputing to the screen. 

```json
result = pretty.Color(json, nil)
```

Will add color to the result for printing to the terminal.
The second param is used for a customizing the style, and passing nil will use the default `pretty.TerminalStyle`.

## Ugly

The following code:
```go
result = pretty.Ugly(example)
```

Will format the json to:

```json
{"name":{"first":"Tom","last":"Anderson"},"age":37,"children":["Sara","Alex","Jack"],"fav.movie":"Deer Hunter","friends":[{"first":"Janet","last":"Murphy","age":44}]}```
```


## Customized output

There's a `PrettyOptions(json, opts)` function which allows for customizing the output with the following options:

```go
type Options struct {
	// Width is an max column width for single line arrays
	// Default is 80
	Width int
	// Prefix is a prefix for all lines
	// Default is an empty string
	Prefix string
	// Indent is the nested indentation
	// Default is two spaces
	Indent string
	// SortKeys will sort the keys alphabetically
	// Default is false
	SortKeys bool
}
```
## Performance

Benchmarks of Pretty alongside the builtin `encoding/json` Indent/Compact methods.
```
BenchmarkPretty-8            1000000     1283 ns/op      720 B/op      2 allocs/op
BenchmarkUgly-8              3000000      426 ns/op      240 B/op      1 allocs/op
BenchmarkUglyInPlace-8       5000000      340 ns/op        0 B/op      0 allocs/op
BenchmarkJSONIndent-8         300000     4628 ns/op     1069 B/op      4 allocs/op
BenchmarkJSONCompact-8       1000000     2469 ns/op      758 B/op      4 allocs/op
```

*These benchmarks were run on a MacBook Pro 15" 2.8 GHz Intel Core i7 using Go 1.7.*

## Contact
Josh Baker [@tidwall](http://twitter.com/tidwall)

## License

Pretty source code is available under the MIT [License](/LICENSE).

GRECT
====

Quickly get the outer rectangle for GeoJSON, WKT, WKB.

```go
	r := grect.Get(`{
      "type": "Polygon",
      "coordinates": [
        [ [100.0, 0.0], [101.0, 0.0], [101.0, 1.0],
          [100.0, 1.0], [100.0, 0.0] ]
        ]
    }`)
	fmt.Printf("%v %v\n", r.Min, r.Max)
	// Output:
	// [100 0] [101 1]
```

## Contact
Josh Baker [@tidwall](http://twitter.com/tidwall)

## License

GRECT source code is available under the MIT [License](/LICENSE).

<p align="center">
<img 
    src="logo.png" 
    width="240" height="78" border="0" alt="GJSON">
<br>
<a href="https://travis-ci.org/tidwall/gjson"><img src="https://img.shields.io/travis/tidwall/gjson.svg?style=flat-square" alt="Build Status"></a>
<a href="https://godoc.org/github.com/tidwall/gjson"><img src="https://img.shields.io/badge/api-reference-blue.svg?style=flat-square" alt="GoDoc"></a>
<a href="http://tidwall.com/gjson-play"><img src="https://img.shields.io/badge/%F0%9F%8F%90-playground-9900cc.svg?style=flat-square" alt="GJSON Playground"></a>
</p>



<p align="center">get json values quickly</a></p>

GJSON is a Go package that provides a [fast](#performance) and [simple](#get-a-value) way to get values from a json document.
It has features such as [one line retrieval](#get-a-value), [dot notation paths](#path-syntax), [iteration](#iterate-through-an-object-or-array), and [parsing json lines](#json-lines).

Also check out [SJSON](https://github.com/tidwall/sjson) for modifying json, and the [JJ](https://github.com/tidwall/jj) command line tool.

Getting Started
===============

## Installing

To start using GJSON, install Go and run `go get`:

```sh
$ go get -u github.com/tidwall/gjson
```

This will retrieve the library.

## Get a value
Get searches json for the specified path. A path is in dot syntax, such as "name.last" or "age". When the value is found it's returned immediately. 

```go
package main

import "github.com/tidwall/gjson"

const json = `{"name":{"first":"Janet","last":"Prichard"},"age":47}`

func main() {
	value := gjson.Get(json, "name.last")
	println(value.String())
}
```

This will print:

```
Prichard
```
*There's also the [GetMany](#get-multiple-values-at-once) function to get multiple values at once, and [GetBytes](#working-with-bytes) for working with JSON byte slices.*

## Path Syntax

Below is a quick overview of the path syntax, for more complete information please
check out [GJSON Syntax](SYNTAX.md).

A path is a series of keys separated by a dot.
A key may contain special wildcard characters '\*' and '?'.
To access an array value use the index as the key.
To get the number of elements in an array or to access a child path, use the '#' character.
The dot and wildcard characters can be escaped with '\\'.

```json
{
  "name": {"first": "Tom", "last": "Anderson"},
  "age":37,
  "children": ["Sara","Alex","Jack"],
  "fav.movie": "Deer Hunter",
  "friends": [
    {"first": "Dale", "last": "Murphy", "age": 44, "nets": ["ig", "fb", "tw"]},
    {"first": "Roger", "last": "Craig", "age": 68, "nets": ["fb", "tw"]},
    {"first": "Jane", "last": "Murphy", "age": 47, "nets": ["ig", "tw"]}
  ]
}
```
```
"name.last"          >> "Anderson"
"age"                >> 37
"children"           >> ["Sara","Alex","Jack"]
"children.#"         >> 3
"children.1"         >> "Alex"
"child*.2"           >> "Jack"
"c?ildren.0"         >> "Sara"
"fav\.movie"         >> "Deer Hunter"
"friends.#.first"    >> ["Dale","Roger","Jane"]
"friends.1.last"     >> "Craig"
```

You can also query an array for the first match by using `#(...)`, or find all 
matches with `#(...)#`. Queries support the `==`, `!=`, `<`, `<=`, `>`, `>=` 
comparison operators and the simple pattern matching `%` (like) and `!%` 
(not like) operators.

```
friends.#(last=="Murphy").first    >> "Dale"
friends.#(last=="Murphy")#.first   >> ["Dale","Jane"]
friends.#(age>45)#.last            >> ["Craig","Murphy"]
friends.#(first%"D*").last         >> "Murphy"
friends.#(first!%"D*").last        >> "Craig"
friends.#(nets.#(=="fb"))#.first   >> ["Dale","Roger"]
```

*Please note that prior to v1.3.0, queries used the `#[...]` brackets. This was
changed in v1.3.0 as to avoid confusion with the new
[multipath](SYNTAX.md#multipaths) syntax. For backwards compatibility, 
`#[...]` will continue to work until the next major release.*

## Result Type

GJSON supports the json types `string`, `number`, `bool`, and `null`. 
Arrays and Objects are returned as their raw json types. 

The `Result` type holds one of these:

```
bool, for JSON booleans
float64, for JSON numbers
string, for JSON string literals
nil, for JSON null
```

To directly access the value:

```go
result.Type    // can be String, Number, True, False, Null, or JSON
result.Str     // holds the string
result.Num     // holds the float64 number
result.Raw     // holds the raw json
result.Index   // index of raw value in original json, zero means index unknown
```

There are a variety of handy functions that work on a result:

```go
result.Exists() bool
result.Value() interface{}
result.Int() int64
result.Uint() uint64
result.Float() float64
result.String() string
result.Bool() bool
result.Time() time.Time
result.Array() []gjson.Result
result.Map() map[string]gjson.Result
result.Get(path string) Result
result.ForEach(iterator func(key, value Result) bool)
result.Less(token Result, caseSensitive bool) bool
```

The `result.Value()` function returns an `interface{}` which requires type assertion and is one of the following Go types:

The `result.Array()` function returns back an array of values.
If the result represents a non-existent value, then an empty array will be returned.
If the result is not a JSON array, the return value will be an array containing one result.

```go
boolean >> bool
number  >> float64
string  >> string
null    >> nil
array   >> []interface{}
object  >> map[string]interface{}
```

### 64-bit integers

The `result.Int()` and `result.Uint()` calls are capable of reading all 64 bits, allowing for large JSON integers.

```go
result.Int() int64    // -9223372036854775808 to 9223372036854775807
result.Uint() int64   // 0 to 18446744073709551615
```

## Modifiers and path chaining 

New in version 1.2 is support for modifier functions and path chaining.

A modifier is a path component that performs custom processing on the 
json.

Multiple paths can be "chained" together using the pipe character. 
This is useful for getting results from a modified query.

For example, using the built-in `@reverse` modifier on the above json document,
we'll get `children` array and reverse the order:

```
"children|@reverse"           >> ["Jack","Alex","Sara"]
"children|@reverse|0"         >> "Jack"
```

There are currently three built-in modifiers:

- `@reverse`: Reverse an array or the members of an object.
- `@ugly`: Remove all whitespace from a json document.
- `@pretty`: Make the json document more human readable.

### Modifier arguments

A modifier may accept an optional argument. The argument can be a valid JSON 
document or just characters.

For example, the `@pretty` modifier takes a json object as its argument. 

```
@pretty:{"sortKeys":true} 
```

Which makes the json pretty and orders all of its keys.

```json
{
  "age":37,
  "children": ["Sara","Alex","Jack"],
  "fav.movie": "Deer Hunter",
  "friends": [
    {"age": 44, "first": "Dale", "last": "Murphy"},
    {"age": 68, "first": "Roger", "last": "Craig"},
    {"age": 47, "first": "Jane", "last": "Murphy"}
  ],
  "name": {"first": "Tom", "last": "Anderson"}
}
```

*The full list of `@pretty` options are `sortKeys`, `indent`, `prefix`, and `width`. 
Please see [Pretty Options](https://github.com/tidwall/pretty#customized-output) for more information.*

### Custom modifiers

You can also add custom modifiers.

For example, here we create a modifier that makes the entire json document upper
or lower case.

```go
gjson.AddModifier("case", func(json, arg string) string {
  if arg == "upper" {
    return strings.ToUpper(json)
  }
  if arg == "lower" {
    return strings.ToLower(json)
  }
  return json
})
```

```
"children|@case:upper"           >> ["SARA","ALEX","JACK"]
"children|@case:lower|@reverse"  >> ["jack","alex","sara"]
```

## JSON Lines

There's support for [JSON Lines](http://jsonlines.org/) using the `..` prefix, which treats a multilined document as an array. 

For example:

```
{"name": "Gilbert", "age": 61}
{"name": "Alexa", "age": 34}
{"name": "May", "age": 57}
{"name": "Deloise", "age": 44}
```

```
..#                   >> 4
..1                   >> {"name": "Alexa", "age": 34}
..3                   >> {"name": "Deloise", "age": 44}
..#.name              >> ["Gilbert","Alexa","May","Deloise"]
..#(name="May").age   >> 57
```

The `ForEachLines` function will iterate through JSON lines.

```go
gjson.ForEachLine(json, func(line gjson.Result) bool{
    println(line.String())
    return true
})
```

## Get nested array values

Suppose you want all the last names from the following json:

```json
{
  "programmers": [
    {
      "firstName": "Janet", 
      "lastName": "McLaughlin", 
    }, {
      "firstName": "Elliotte", 
      "lastName": "Hunter", 
    }, {
      "firstName": "Jason", 
      "lastName": "Harold", 
    }
  ]
}
```

You would use the path "programmers.#.lastName" like such:

```go
result := gjson.Get(json, "programmers.#.lastName")
for _, name := range result.Array() {
	println(name.String())
}
```

You can also query an object inside an array:

```go
name := gjson.Get(json, `programmers.#(lastName="Hunter").firstName`)
println(name.String())  // prints "Elliotte"
```

## Iterate through an object or array

The `ForEach` function allows for quickly iterating through an object or array. 
The key and value are passed to the iterator function for objects.
Only the value is passed for arrays.
Returning `false` from an iterator will stop iteration.

```go
result := gjson.Get(json, "programmers")
result.ForEach(func(key, value gjson.Result) bool {
	println(value.String()) 
	return true // keep iterating
})
```

## Simple Parse and Get

There's a `Parse(json)` function that will do a simple parse, and `result.Get(path)` that will search a result.

For example, all of these will return the same result:

```go
gjson.Parse(json).Get("name").Get("last")
gjson.Get(json, "name").Get("last")
gjson.Get(json, "name.last")
```

## Check for the existence of a value

Sometimes you just want to know if a value exists. 

```go
value := gjson.Get(json, "name.last")
if !value.Exists() {
	println("no last name")
} else {
	println(value.String())
}

// Or as one step
if gjson.Get(json, "name.last").Exists() {
	println("has a last name")
}
```

## Validate JSON

The `Get*` and `Parse*` functions expects that the json is well-formed. Bad json will not panic, but it may return back unexpected results.

If you are consuming JSON from an unpredictable source then you may want to validate prior to using GJSON.

```go
if !gjson.Valid(json) {
	return errors.New("invalid json")
}
value := gjson.Get(json, "name.last")
```

## Unmarshal to a map

To unmarshal to a `map[string]interface{}`:

```go
m, ok := gjson.Parse(json).Value().(map[string]interface{})
if !ok {
	// not a map
}
```

## Working with Bytes

If your JSON is contained in a `[]byte` slice, there's the [GetBytes](https://godoc.org/github.com/tidwall/gjson#GetBytes) function. This is preferred over `Get(string(data), path)`.

```go
var json []byte = ...
result := gjson.GetBytes(json, path)
```

If you are using the `gjson.GetBytes(json, path)` function and you want to avoid converting `result.Raw` to a `[]byte`, then you can use this pattern:

```go
var json []byte = ...
result := gjson.GetBytes(json, path)
var raw []byte
if result.Index > 0 {
    raw = json[result.Index:result.Index+len(result.Raw)]
} else {
    raw = []byte(result.Raw)
}
```

This is a best-effort no allocation sub slice of the original json. This method utilizes the `result.Index` field, which is the position of the raw data in the original json. It's possible that the value of `result.Index` equals zero, in which case the `result.Raw` is converted to a `[]byte`.

## Get multiple values at once

The `GetMany` function can be used to get multiple values at the same time.

```go
results := gjson.GetMany(json, "name.first", "name.last", "age")
```

The return value is a `[]Result`, which will always contain exactly the same number of items as the input paths.

## Performance

Benchmarks of GJSON alongside [encoding/json](https://golang.org/pkg/encoding/json/), 
[ffjson](https://github.com/pquerna/ffjson), 
[EasyJSON](https://github.com/mailru/easyjson),
[jsonparser](https://github.com/buger/jsonparser),
and [json-iterator](https://github.com/json-iterator/go)

```
BenchmarkGJSONGet-8                  3000000        372 ns/op          0 B/op         0 allocs/op
BenchmarkGJSONUnmarshalMap-8          900000       4154 ns/op       1920 B/op        26 allocs/op
BenchmarkJSONUnmarshalMap-8           600000       9019 ns/op       3048 B/op        69 allocs/op
BenchmarkJSONDecoder-8                300000      14120 ns/op       4224 B/op       184 allocs/op
BenchmarkFFJSONLexer-8               1500000       3111 ns/op        896 B/op         8 allocs/op
BenchmarkEasyJSONLexer-8             3000000        887 ns/op        613 B/op         6 allocs/op
BenchmarkJSONParserGet-8             3000000        499 ns/op         21 B/op         0 allocs/op
BenchmarkJSONIterator-8              3000000        812 ns/op        544 B/op         9 allocs/op
```

JSON document used:

```json
{
  "widget": {
    "debug": "on",
    "window": {
      "title": "Sample Konfabulator Widget",
      "name": "main_window",
      "width": 500,
      "height": 500
    },
    "image": { 
      "src": "Images/Sun.png",
      "hOffset": 250,
      "vOffset": 250,
      "alignment": "center"
    },
    "text": {
      "data": "Click Here",
      "size": 36,
      "style": "bold",
      "vOffset": 100,
      "alignment": "center",
      "onMouseUp": "sun1.opacity = (sun1.opacity / 100) * 90;"
    }
  }
}    
```

Each operation was rotated though one of the following search paths:

```
widget.window.name
widget.image.hOffset
widget.text.onMouseUp
```

*These benchmarks were run on a MacBook Pro 15" 2.8 GHz Intel Core i7 using Go 1.8 and can be be found [here](https://github.com/tidwall/gjson-benchmarks).*


## Contact
Josh Baker [@tidwall](http://twitter.com/tidwall)

## License

GJSON source code is available under the MIT [License](/LICENSE).
# go-vhost
go-vhost is a simple library that lets you implement virtual hosting functionality for different protocols (HTTP and TLS so far). go-vhost has a high-level and a low-level interface. The high-level interface lets you wrap existing net.Listeners with "muxer" objects. You can then Listen() on a muxer for a particular virtual host name of interest which will return to you a net.Listener for just connections with the virtual hostname of interest.

The lower-level go-vhost interface are just functions which extract the name/routing information for the given protocol and return an object implementing net.Conn which works as if no bytes had been consumed.

### [API Documentation](https://godoc.org/github.com/inconshreveable/go-vhost)

### Usage
```go
l, _ := net.Listen("tcp", *listen)

// start multiplexing on it
mux, _ := vhost.NewHTTPMuxer(l, muxTimeout)

// listen for connections to different domains
for _, v := range virtualHosts {
	vhost := v

	// vhost.Name is a virtual hostname like "foo.example.com"
	muxListener, _ := mux.Listen(vhost.Name())

	go func(vh virtualHost, ml net.Listener) {
		for {
			conn, _ := ml.Accept()
			go vh.Handle(conn)
		}
	}(vhost, muxListener)
}

for {
	conn, err := mux.NextError()

	switch err.(type) {
	case vhost.BadRequest:
		log.Printf("got a bad request!")
		conn.Write([]byte("bad request"))
	case vhost.NotFound:
		log.Printf("got a connection for an unknown vhost")
		conn.Write([]byte("vhost not found"))
	case vhost.Closed:
		log.Printf("closed conn: %s", err)
	default:
		if conn != nil {
			conn.Write([]byte("server error"))
		}
	}

	if conn != nil {
		conn.Close()
	}
}
```
### Low-level API usage
```go
// accept a new connection
conn, _ := listener.Accept()

// parse out the HTTP request and the Host header
if vhostConn, err = vhost.HTTP(conn); err != nil {
	panic("Not a valid http connection!")
}

fmt.Printf("Target Host: ", vhostConn.Host())
// Target Host: example.com

// vhostConn contains the entire request as if no bytes had been consumed
bytes, _ := ioutil.ReadAll(vhostConn)
fmt.Printf("%s", bytes)
// GET / HTTP/1.1
// Host: example.com
// User-Agent: ...
// ...
```

### Advanced introspection
The entire HTTP request headers are available for inspection in case you want to mux on something besides the Host header:
```go
// parse out the HTTP request and the Host header
if vhostConn, err = vhost.HTTP(conn); err != nil {
	panic("Not a valid http connection!")
}

httpVersion := vhost.Request.MinorVersion
customRouting := vhost.Request.Header["X-Custom-Routing-Header"]
```

Likewise for TLS, you can look at detailed information about the ClientHello message:
```go
if vhostConn, err = vhost.TLS(conn); err != nil {
	panic("Not a valid TLS connection!")
}

cipherSuites := vhost.ClientHelloMsg.CipherSuites
sessionId := vhost.ClientHelloMsg.SessionId
```

##### Memory reduction with Free
After you're done muxing, you probably don't need to inspect the header data anymore, so you can make it available for garbage collection:

```go
// look up the upstream host
upstreamHost := hostMapping[vhostConn.Host()]

// free up the muxing data
vhostConn.Free()

// vhostConn.Host() == ""
// vhostConn.Request == nil (HTTP)
// vhostConn.ClientHelloMsg == nil (TLS)
```
# File system notifications for Go

[![GoDoc](https://godoc.org/github.com/fsnotify/fsnotify?status.svg)](https://godoc.org/github.com/fsnotify/fsnotify) [![Go Report Card](https://goreportcard.com/badge/github.com/fsnotify/fsnotify)](https://goreportcard.com/report/github.com/fsnotify/fsnotify)

fsnotify utilizes [golang.org/x/sys](https://godoc.org/golang.org/x/sys) rather than `syscall` from the standard library. Ensure you have the latest version installed by running:

```console
go get -u golang.org/x/sys/...
```

Cross platform: Windows, Linux, BSD and macOS.

|Adapter   |OS        |Status    |
|----------|----------|----------|
|inotify   |Linux 2.6.27 or later, Android\*|Supported [![Build Status](https://travis-ci.org/fsnotify/fsnotify.svg?branch=master)](https://travis-ci.org/fsnotify/fsnotify)|
|kqueue    |BSD, macOS, iOS\*|Supported [![Build Status](https://travis-ci.org/fsnotify/fsnotify.svg?branch=master)](https://travis-ci.org/fsnotify/fsnotify)|
|ReadDirectoryChangesW|Windows|Supported [![Build status](https://ci.appveyor.com/api/projects/status/ivwjubaih4r0udeh/branch/master?svg=true)](https://ci.appveyor.com/project/NathanYoungman/fsnotify/branch/master)|
|FSEvents  |macOS         |[Planned](https://github.com/fsnotify/fsnotify/issues/11)|
|FEN       |Solaris 11    |[In Progress](https://github.com/fsnotify/fsnotify/issues/12)|
|fanotify  |Linux 2.6.37+ | |
|USN Journals |Windows    |[Maybe](https://github.com/fsnotify/fsnotify/issues/53)|
|Polling   |*All*         |[Maybe](https://github.com/fsnotify/fsnotify/issues/9)|

\* Android and iOS are untested.

Please see [the documentation](https://godoc.org/github.com/fsnotify/fsnotify) and consult the [FAQ](#faq) for usage information.

## API stability

fsnotify is a fork of [howeyc/fsnotify](https://godoc.org/github.com/howeyc/fsnotify) with a new API as of v1.0. The API is based on [this design document](http://goo.gl/MrYxyA). 

All [releases](https://github.com/fsnotify/fsnotify/releases) are tagged based on [Semantic Versioning](http://semver.org/). Further API changes are [planned](https://github.com/fsnotify/fsnotify/milestones), and will be tagged with a new major revision number.

Go 1.6 supports dependencies located in the `vendor/` folder. Unless you are creating a library, it is recommended that you copy fsnotify into `vendor/github.com/fsnotify/fsnotify` within your project, and likewise for `golang.org/x/sys`.

## Contributing

Please refer to [CONTRIBUTING][] before opening an issue or pull request.

## Example

See [example_test.go](https://github.com/fsnotify/fsnotify/blob/master/example_test.go).

## FAQ

**When a file is moved to another directory is it still being watched?**

No (it shouldn't be, unless you are watching where it was moved to).

**When I watch a directory, are all subdirectories watched as well?**

No, you must add watches for any directory you want to watch (a recursive watcher is on the roadmap [#18][]).

**Do I have to watch the Error and Event channels in a separate goroutine?**

As of now, yes. Looking into making this single-thread friendly (see [howeyc #7][#7])

**Why am I receiving multiple events for the same file on OS X?**

Spotlight indexing on OS X can result in multiple events (see [howeyc #62][#62]). A temporary workaround is to add your folder(s) to the *Spotlight Privacy settings* until we have a native FSEvents implementation (see [#11][]).

**How many files can be watched at once?**

There are OS-specific limits as to how many watches can be created:
* Linux: /proc/sys/fs/inotify/max_user_watches contains the limit, reaching this limit results in a "no space left on device" error.
* BSD / OSX: sysctl variables "kern.maxfiles" and "kern.maxfilesperproc", reaching these limits results in a "too many open files" error.

[#62]: https://github.com/howeyc/fsnotify/issues/62
[#18]: https://github.com/fsnotify/fsnotify/issues/18
[#11]: https://github.com/fsnotify/fsnotify/issues/11
[#7]: https://github.com/howeyc/fsnotify/issues/7

[contributing]: https://github.com/fsnotify/fsnotify/blob/master/CONTRIBUTING.md

## Related Projects

* [notify](https://github.com/rjeczalik/notify)
* [fsevents](https://github.com/fsnotify/fsevents)

# Color [![GoDoc](https://godoc.org/github.com/fatih/color?status.svg)](https://godoc.org/github.com/fatih/color) [![Build Status](https://img.shields.io/travis/fatih/color.svg?style=flat-square)](https://travis-ci.org/fatih/color)



Color lets you use colorized outputs in terms of [ANSI Escape
Codes](http://en.wikipedia.org/wiki/ANSI_escape_code#Colors) in Go (Golang). It
has support for Windows too! The API can be used in several ways, pick one that
suits you.


![Color](https://i.imgur.com/c1JI0lA.png)


## Install

```bash
go get github.com/fatih/color
```

Note that the `vendor` folder is here for stability. Remove the folder if you
already have the dependencies in your GOPATH.

## Examples

### Standard colors

```go
// Print with default helper functions
color.Cyan("Prints text in cyan.")

// A newline will be appended automatically
color.Blue("Prints %s in blue.", "text")

// These are using the default foreground colors
color.Red("We have red")
color.Magenta("And many others ..")

```

### Mix and reuse colors

```go
// Create a new color object
c := color.New(color.FgCyan).Add(color.Underline)
c.Println("Prints cyan text with an underline.")

// Or just add them to New()
d := color.New(color.FgCyan, color.Bold)
d.Printf("This prints bold cyan %s\n", "too!.")

// Mix up foreground and background colors, create new mixes!
red := color.New(color.FgRed)

boldRed := red.Add(color.Bold)
boldRed.Println("This will print text in bold red.")

whiteBackground := red.Add(color.BgWhite)
whiteBackground.Println("Red text with white background.")
```

### Use your own output (io.Writer)

```go
// Use your own io.Writer output
color.New(color.FgBlue).Fprintln(myWriter, "blue color!")

blue := color.New(color.FgBlue)
blue.Fprint(writer, "This will print text in blue.")
```

### Custom print functions (PrintFunc)

```go
// Create a custom print function for convenience
red := color.New(color.FgRed).PrintfFunc()
red("Warning")
red("Error: %s", err)

// Mix up multiple attributes
notice := color.New(color.Bold, color.FgGreen).PrintlnFunc()
notice("Don't forget this...")
```

### Custom fprint functions (FprintFunc)

```go
blue := color.New(FgBlue).FprintfFunc()
blue(myWriter, "important notice: %s", stars)

// Mix up with multiple attributes
success := color.New(color.Bold, color.FgGreen).FprintlnFunc()
success(myWriter, "Don't forget this...")
```

### Insert into noncolor strings (SprintFunc)

```go
// Create SprintXxx functions to mix strings with other non-colorized strings:
yellow := color.New(color.FgYellow).SprintFunc()
red := color.New(color.FgRed).SprintFunc()
fmt.Printf("This is a %s and this is %s.\n", yellow("warning"), red("error"))

info := color.New(color.FgWhite, color.BgGreen).SprintFunc()
fmt.Printf("This %s rocks!\n", info("package"))

// Use helper functions
fmt.Println("This", color.RedString("warning"), "should be not neglected.")
fmt.Printf("%v %v\n", color.GreenString("Info:"), "an important message.")

// Windows supported too! Just don't forget to change the output to color.Output
fmt.Fprintf(color.Output, "Windows support: %s", color.GreenString("PASS"))
```

### Plug into existing code

```go
// Use handy standard colors
color.Set(color.FgYellow)

fmt.Println("Existing text will now be in yellow")
fmt.Printf("This one %s\n", "too")

color.Unset() // Don't forget to unset

// You can mix up parameters
color.Set(color.FgMagenta, color.Bold)
defer color.Unset() // Use it in your function

fmt.Println("All text will now be bold magenta.")
```

### Disable/Enable color
 
There might be a case where you want to explicitly disable/enable color output. the 
`go-isatty` package will automatically disable color output for non-tty output streams 
(for example if the output were piped directly to `less`)

`Color` has support to disable/enable colors both globally and for single color 
definitions. For example suppose you have a CLI app and a `--no-color` bool flag. You 
can easily disable the color output with:

```go

var flagNoColor = flag.Bool("no-color", false, "Disable color output")

if *flagNoColor {
	color.NoColor = true // disables colorized output
}
```

It also has support for single color definitions (local). You can
disable/enable color output on the fly:

```go
c := color.New(color.FgCyan)
c.Println("Prints cyan text")

c.DisableColor()
c.Println("This is printed without any color")

c.EnableColor()
c.Println("This prints again cyan...")
```

## Todo

* Save/Return previous values
* Evaluate fmt.Formatter interface


## Credits

 * [Fatih Arslan](https://github.com/fatih)
 * Windows support via @mattn: [colorable](https://github.com/mattn/go-colorable)

## License

The MIT License (MIT) - see [`LICENSE.md`](https://github.com/fatih/color/blob/master/LICENSE.md) for more details

[![Build Status](https://travis-ci.org/spf13/pflag.svg?branch=master)](https://travis-ci.org/spf13/pflag)
[![Go Report Card](https://goreportcard.com/badge/github.com/spf13/pflag)](https://goreportcard.com/report/github.com/spf13/pflag)
[![GoDoc](https://godoc.org/github.com/spf13/pflag?status.svg)](https://godoc.org/github.com/spf13/pflag)

## Description

pflag is a drop-in replacement for Go's flag package, implementing
POSIX/GNU-style --flags.

pflag is compatible with the [GNU extensions to the POSIX recommendations
for command-line options][1]. For a more precise description, see the
"Command-line flag syntax" section below.

[1]: http://www.gnu.org/software/libc/manual/html_node/Argument-Syntax.html

pflag is available under the same style of BSD license as the Go language,
which can be found in the LICENSE file.

## Installation

pflag is available using the standard `go get` command.

Install by running:

    go get github.com/spf13/pflag

Run tests by running:

    go test github.com/spf13/pflag

## Usage

pflag is a drop-in replacement of Go's native flag package. If you import
pflag under the name "flag" then all code should continue to function
with no changes.

``` go
import flag "github.com/spf13/pflag"
```

There is one exception to this: if you directly instantiate the Flag struct
there is one more field "Shorthand" that you will need to set.
Most code never instantiates this struct directly, and instead uses
functions such as String(), BoolVar(), and Var(), and is therefore
unaffected.

Define flags using flag.String(), Bool(), Int(), etc.

This declares an integer flag, -flagname, stored in the pointer ip, with type *int.

``` go
var ip *int = flag.Int("flagname", 1234, "help message for flagname")
```

If you like, you can bind the flag to a variable using the Var() functions.

``` go
var flagvar int
func init() {
    flag.IntVar(&flagvar, "flagname", 1234, "help message for flagname")
}
```

Or you can create custom flags that satisfy the Value interface (with
pointer receivers) and couple them to flag parsing by

``` go
flag.Var(&flagVal, "name", "help message for flagname")
```

For such flags, the default value is just the initial value of the variable.

After all flags are defined, call

``` go
flag.Parse()
```

to parse the command line into the defined flags.

Flags may then be used directly. If you're using the flags themselves,
they are all pointers; if you bind to variables, they're values.

``` go
fmt.Println("ip has value ", *ip)
fmt.Println("flagvar has value ", flagvar)
```

There are helpers function to get values later if you have the FlagSet but
it was difficult to keep up with all of the flag pointers in your code.
If you have a pflag.FlagSet with a flag called 'flagname' of type int you
can use GetInt() to get the int value. But notice that 'flagname' must exist
and it must be an int. GetString("flagname") will fail.

``` go
i, err := flagset.GetInt("flagname")
```

After parsing, the arguments after the flag are available as the
slice flag.Args() or individually as flag.Arg(i).
The arguments are indexed from 0 through flag.NArg()-1.

The pflag package also defines some new functions that are not in flag,
that give one-letter shorthands for flags. You can use these by appending
'P' to the name of any function that defines a flag.

``` go
var ip = flag.IntP("flagname", "f", 1234, "help message")
var flagvar bool
func init() {
	flag.BoolVarP(&flagvar, "boolname", "b", true, "help message")
}
flag.VarP(&flagVal, "varname", "v", "help message")
```

Shorthand letters can be used with single dashes on the command line.
Boolean shorthand flags can be combined with other shorthand flags.

The default set of command-line flags is controlled by
top-level functions.  The FlagSet type allows one to define
independent sets of flags, such as to implement subcommands
in a command-line interface. The methods of FlagSet are
analogous to the top-level functions for the command-line
flag set.

## Setting no option default values for flags

After you create a flag it is possible to set the pflag.NoOptDefVal for
the given flag. Doing this changes the meaning of the flag slightly. If
a flag has a NoOptDefVal and the flag is set on the command line without
an option the flag will be set to the NoOptDefVal. For example given:

``` go
var ip = flag.IntP("flagname", "f", 1234, "help message")
flag.Lookup("flagname").NoOptDefVal = "4321"
```

Would result in something like

| Parsed Arguments | Resulting Value |
| -------------    | -------------   |
| --flagname=1357  | ip=1357         |
| --flagname       | ip=4321         |
| [nothing]        | ip=1234         |

## Command line flag syntax

```
--flag    // boolean flags, or flags with no option default values
--flag x  // only on flags without a default value
--flag=x
```

Unlike the flag package, a single dash before an option means something
different than a double dash. Single dashes signify a series of shorthand
letters for flags. All but the last shorthand letter must be boolean flags
or a flag with a default value

```
// boolean or flags where the 'no option default value' is set
-f
-f=true
-abc
but
-b true is INVALID

// non-boolean and flags without a 'no option default value'
-n 1234
-n=1234
-n1234

// mixed
-abcs "hello"
-absd="hello"
-abcs1234
```

Flag parsing stops after the terminator "--". Unlike the flag package,
flags can be interspersed with arguments anywhere on the command line
before this terminator.

Integer flags accept 1234, 0664, 0x1234 and may be negative.
Boolean flags (in their long form) accept 1, 0, t, f, true, false,
TRUE, FALSE, True, False.
Duration flags accept any input valid for time.ParseDuration.

## Mutating or "Normalizing" Flag names

It is possible to set a custom flag name 'normalization function.' It allows flag names to be mutated both when created in the code and when used on the command line to some 'normalized' form. The 'normalized' form is used for comparison. Two examples of using the custom normalization func follow.

**Example #1**: You want -, _, and . in flags to compare the same. aka --my-flag == --my_flag == --my.flag

``` go
func wordSepNormalizeFunc(f *pflag.FlagSet, name string) pflag.NormalizedName {
	from := []string{"-", "_"}
	to := "."
	for _, sep := range from {
		name = strings.Replace(name, sep, to, -1)
	}
	return pflag.NormalizedName(name)
}

myFlagSet.SetNormalizeFunc(wordSepNormalizeFunc)
```

**Example #2**: You want to alias two flags. aka --old-flag-name == --new-flag-name

``` go
func aliasNormalizeFunc(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "old-flag-name":
		name = "new-flag-name"
		break
	}
	return pflag.NormalizedName(name)
}

myFlagSet.SetNormalizeFunc(aliasNormalizeFunc)
```

## Deprecating a flag or its shorthand
It is possible to deprecate a flag, or just its shorthand. Deprecating a flag/shorthand hides it from help text and prints a usage message when the deprecated flag/shorthand is used.

**Example #1**: You want to deprecate a flag named "badflag" as well as inform the users what flag they should use instead.
```go
// deprecate a flag by specifying its name and a usage message
flags.MarkDeprecated("badflag", "please use --good-flag instead")
```
This hides "badflag" from help text, and prints `Flag --badflag has been deprecated, please use --good-flag instead` when "badflag" is used.

**Example #2**: You want to keep a flag name "noshorthandflag" but deprecate its shortname "n".
```go
// deprecate a flag shorthand by specifying its flag name and a usage message
flags.MarkShorthandDeprecated("noshorthandflag", "please use --noshorthandflag only")
```
This hides the shortname "n" from help text, and prints `Flag shorthand -n has been deprecated, please use --noshorthandflag only` when the shorthand "n" is used.

Note that usage message is essential here, and it should not be empty.

## Hidden flags
It is possible to mark a flag as hidden, meaning it will still function as normal, however will not show up in usage/help text.

**Example**: You have a flag named "secretFlag" that you need for internal use only and don't want it showing up in help text, or for its usage text to be available.
```go
// hide a flag by specifying its name
flags.MarkHidden("secretFlag")
```

## Disable sorting of flags
`pflag` allows you to disable sorting of flags for help and usage message.

**Example**:
```go
flags.BoolP("verbose", "v", false, "verbose output")
flags.String("coolflag", "yeaah", "it's really cool flag")
flags.Int("usefulflag", 777, "sometimes it's very useful")
flags.SortFlags = false
flags.PrintDefaults()
```
**Output**:
```
  -v, --verbose           verbose output
      --coolflag string   it's really cool flag (default "yeaah")
      --usefulflag int    sometimes it's very useful (default 777)
```


## Supporting Go flags when using pflag
In order to support flags defined using Go's `flag` package, they must be added to the `pflag` flagset. This is usually necessary
to support flags defined by third-party dependencies (e.g. `golang/glog`).

**Example**: You want to add the Go flags to the `CommandLine` flagset
```go
import (
	goflag "flag"
	flag "github.com/spf13/pflag"
)

var ip *int = flag.Int("flagname", 1234, "help message for flagname")

func main() {
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	flag.Parse()
}
```

## More info

You can see the full reference documentation of the pflag package
[at godoc.org][3], or through go's standard documentation system by
running `godoc -http=:6060` and browsing to
[http://localhost:6060/pkg/github.com/spf13/pflag][2] after
installation.

[2]: http://localhost:6060/pkg/github.com/spf13/pflag
[3]: http://godoc.org/github.com/spf13/pflag
jWalterWeatherman
=================

Seamless printing to the terminal (stdout) and logging to a io.Writer
(file) that’s as easy to use as fmt.Println.

![and_that__s_why_you_always_leave_a_note_by_jonnyetc-d57q7um](https://cloud.githubusercontent.com/assets/173412/11002937/ccd01654-847d-11e5-828e-12ebaf582eaf.jpg)
Graphic by [JonnyEtc](http://jonnyetc.deviantart.com/art/And-That-s-Why-You-Always-Leave-a-Note-315311422)

JWW is primarily a wrapper around the excellent standard log library. It
provides a few advantages over using the standard log library alone.

1. Ready to go out of the box. 
2. One library for both printing to the terminal and logging (to files).
3. Really easy to log to either a temp file or a file you specify.


I really wanted a very straightforward library that could seamlessly do
the following things.

1. Replace all the println, printf, etc statements thoughout my code with
   something more useful
2. Allow the user to easily control what levels are printed to stdout
3. Allow the user to easily control what levels are logged
4. Provide an easy mechanism (like fmt.Println) to print info to the user
   which can be easily logged as well 
5. Due to 2 & 3 provide easy verbose mode for output and logs
6. Not have any unnecessary initialization cruft. Just use it.

# Usage

## Step 1. Use it
Put calls throughout your source based on type of feedback.
No initialization or setup needs to happen. Just start calling things.

Available Loggers are:

 * TRACE
 * DEBUG
 * INFO
 * WARN
 * ERROR
 * CRITICAL
 * FATAL

These each are loggers based on the log standard library and follow the
standard usage. Eg.

```go
    import (
        jww "github.com/spf13/jwalterweatherman"
    )

    ...

    if err != nil {

        // This is a pretty serious error and the user should know about
        // it. It will be printed to the terminal as well as logged under the
        // default thresholds.

        jww.ERROR.Println(err)
    }

    if err2 != nil {
        // This error isn’t going to materially change the behavior of the
        // application, but it’s something that may not be what the user
        // expects. Under the default thresholds, Warn will be logged, but
        // not printed to the terminal. 

        jww.WARN.Println(err2)
    }

    // Information that’s relevant to what’s happening, but not very
    // important for the user. Under the default thresholds this will be
    // discarded.

    jww.INFO.Printf("information %q", response)

```

NOTE: You can also use the library in a non-global setting by creating an instance of a Notebook:

```go
notepad = jww.NewNotepad(jww.LevelInfo, jww.LevelTrace, os.Stdout, ioutil.Discard, "", log.Ldate|log.Ltime)
notepad.WARN.Println("Some warning"")
```

_Why 7 levels?_

Maybe you think that 7 levels are too much for any application... and you
are probably correct. Just because there are seven levels doesn’t mean
that you should be using all 7 levels. Pick the right set for your needs.
Remember they only have to mean something to your project.

## Step 2. Optionally configure JWW

Under the default thresholds :

 * Debug, Trace & Info goto /dev/null
 * Warn and above is logged (when a log file/io.Writer is provided)
 * Error and above is printed to the terminal (stdout)

### Changing the thresholds

The threshold can be changed at any time, but will only affect calls that
execute after the change was made.

This is very useful if your application has a verbose mode. Of course you
can decide what verbose means to you or even have multiple levels of
verbosity.


```go
    import (
        jww "github.com/spf13/jwalterweatherman"
    )

    if Verbose {
        jww.SetLogThreshold(jww.LevelTrace)
        jww.SetStdoutThreshold(jww.LevelInfo)
    }
```

Note that JWW's own internal output uses log levels as well, so set the log
level before making any other calls if you want to see what it's up to.


### Setting a log file

JWW can log to any `io.Writer`:


```go

    jww.SetLogOutput(customWriter) 

```


# More information

This is an early release. I’ve been using it for a while and this is the
third interface I’ve tried. I like this one pretty well, but no guarantees
that it won’t change a bit.

I wrote this for use in [hugo](https://gohugo.io). If you are looking
for a static website engine that’s super fast please checkout Hugo.
![viper logo](https://cloud.githubusercontent.com/assets/173412/10886745/998df88a-8151-11e5-9448-4736db51020d.png)

Go configuration with fangs!

Many Go projects are built using Viper including:

* [Hugo](http://gohugo.io)
* [EMC RexRay](http://rexray.readthedocs.org/en/stable/)
* [Imgur’s Incus](https://github.com/Imgur/incus)
* [Nanobox](https://github.com/nanobox-io/nanobox)/[Nanopack](https://github.com/nanopack)
* [Docker Notary](https://github.com/docker/Notary)
* [BloomApi](https://www.bloomapi.com/)
* [doctl](https://github.com/digitalocean/doctl)
* [Clairctl](https://github.com/jgsqware/clairctl)

[![Build Status](https://travis-ci.org/spf13/viper.svg)](https://travis-ci.org/spf13/viper) [![Join the chat at https://gitter.im/spf13/viper](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/spf13/viper?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![GoDoc](https://godoc.org/github.com/spf13/viper?status.svg)](https://godoc.org/github.com/spf13/viper)


## What is Viper?

Viper is a complete configuration solution for Go applications including 12-Factor apps. It is designed
to work within an application, and can handle all types of configuration needs
and formats. It supports:

* setting defaults
* reading from JSON, TOML, YAML, HCL, and Java properties config files
* live watching and re-reading of config files (optional)
* reading from environment variables
* reading from remote config systems (etcd or Consul), and watching changes
* reading from command line flags
* reading from buffer
* setting explicit values

Viper can be thought of as a registry for all of your applications
configuration needs.

## Why Viper?

When building a modern application, you don’t want to worry about
configuration file formats; you want to focus on building awesome software.
Viper is here to help with that.

Viper does the following for you:

1. Find, load, and unmarshal a configuration file in JSON, TOML, YAML, HCL, or Java properties formats.
2. Provide a mechanism to set default values for your different
   configuration options.
3. Provide a mechanism to set override values for options specified through
   command line flags.
4. Provide an alias system to easily rename parameters without breaking existing
   code.
5. Make it easy to tell the difference between when a user has provided a
   command line or config file which is the same as the default.

Viper uses the following precedence order. Each item takes precedence over the
item below it:

 * explicit call to Set
 * flag
 * env
 * config
 * key/value store
 * default

Viper configuration keys are case insensitive.

## Putting Values into Viper

### Establishing Defaults

A good configuration system will support default values. A default value is not
required for a key, but it’s useful in the event that a key hasn’t been set via
config file, environment variable, remote configuration or flag.

Examples:

```go
viper.SetDefault("ContentDir", "content")
viper.SetDefault("LayoutDir", "layouts")
viper.SetDefault("Taxonomies", map[string]string{"tag": "tags", "category": "categories"})
```

### Reading Config Files

Viper requires minimal configuration so it knows where to look for config files.
Viper supports JSON, TOML, YAML, HCL, and Java Properties files. Viper can search multiple paths, but
currently a single Viper instance only supports a single configuration file.
Viper does not default to any configuration search paths leaving defaults decision
to an application.

Here is an example of how to use Viper to search for and read a configuration file.
None of the specific paths are required, but at least one path should be provided
where a configuration file is expected.

```go
viper.SetConfigName("config") // name of config file (without extension)
viper.AddConfigPath("/etc/appname/")   // path to look for the config file in
viper.AddConfigPath("$HOME/.appname")  // call multiple times to add many search paths
viper.AddConfigPath(".")               // optionally look for config in the working directory
err := viper.ReadInConfig() // Find and read the config file
if err != nil { // Handle errors reading the config file
	panic(fmt.Errorf("Fatal error config file: %s \n", err))
}
```

### Watching and re-reading config files

Viper supports the ability to have your application live read a config file while running.

Gone are the days of needing to restart a server to have a config take effect,
viper powered applications can read an update to a config file while running and
not miss a beat.

Simply tell the viper instance to watchConfig.
Optionally you can provide a function for Viper to run each time a change occurs.

**Make sure you add all of the configPaths prior to calling `WatchConfig()`**

```go
viper.WatchConfig()
viper.OnConfigChange(func(e fsnotify.Event) {
	fmt.Println("Config file changed:", e.Name)
})
```

### Reading Config from io.Reader

Viper predefines many configuration sources such as files, environment
variables, flags, and remote K/V store, but you are not bound to them. You can
also implement your own required configuration source and feed it to viper.

```go
viper.SetConfigType("yaml") // or viper.SetConfigType("YAML")

// any approach to require this configuration into your program.
var yamlExample = []byte(`
Hacker: true
name: steve
hobbies:
- skateboarding
- snowboarding
- go
clothing:
  jacket: leather
  trousers: denim
age: 35
eyes : brown
beard: true
`)

viper.ReadConfig(bytes.NewBuffer(yamlExample))

viper.Get("name") // this would be "steve"
```

### Setting Overrides

These could be from a command line flag, or from your own application logic.

```go
viper.Set("Verbose", true)
viper.Set("LogFile", LogFile)
```

### Registering and Using Aliases

Aliases permit a single value to be referenced by multiple keys

```go
viper.RegisterAlias("loud", "Verbose")

viper.Set("verbose", true) // same result as next line
viper.Set("loud", true)   // same result as prior line

viper.GetBool("loud") // true
viper.GetBool("verbose") // true
```

### Working with Environment Variables

Viper has full support for environment variables. This enables 12 factor
applications out of the box. There are five methods that exist to aid working
with ENV:

 * `AutomaticEnv()`
 * `BindEnv(string...) : error`
 * `SetEnvPrefix(string)`
 * `SetEnvKeyReplacer(string...) *strings.Replacer`
  * `AllowEmptyEnvVar(bool)`

_When working with ENV variables, it’s important to recognize that Viper
treats ENV variables as case sensitive._

Viper provides a mechanism to try to ensure that ENV variables are unique. By
using `SetEnvPrefix`, you can tell Viper to use a prefix while reading from
the environment variables. Both `BindEnv` and `AutomaticEnv` will use this
prefix.

`BindEnv` takes one or two parameters. The first parameter is the key name, the
second is the name of the environment variable. The name of the environment
variable is case sensitive. If the ENV variable name is not provided, then
Viper will automatically assume that the key name matches the ENV variable name,
but the ENV variable is IN ALL CAPS. When you explicitly provide the ENV
variable name, it **does not** automatically add the prefix.

One important thing to recognize when working with ENV variables is that the
value will be read each time it is accessed. Viper does not fix the value when
the `BindEnv` is called.

`AutomaticEnv` is a powerful helper especially when combined with
`SetEnvPrefix`. When called, Viper will check for an environment variable any
time a `viper.Get` request is made. It will apply the following rules. It will
check for a environment variable with a name matching the key uppercased and
prefixed with the `EnvPrefix` if set.

`SetEnvKeyReplacer` allows you to use a `strings.Replacer` object to rewrite Env
keys to an extent. This is useful if you want to use `-` or something in your
`Get()` calls, but want your environmental variables to use `_` delimiters. An
example of using it can be found in `viper_test.go`.

By default empty environment variables are considered unset and will fall back to
the next configuration source. To treat empty environment variables as set, use
the `AllowEmptyEnv` method.

#### Env example

```go
SetEnvPrefix("spf") // will be uppercased automatically
BindEnv("id")

os.Setenv("SPF_ID", "13") // typically done outside of the app

id := Get("id") // 13
```

### Working with Flags

Viper has the ability to bind to flags. Specifically, Viper supports `Pflags`
as used in the [Cobra](https://github.com/spf13/cobra) library.

Like `BindEnv`, the value is not set when the binding method is called, but when
it is accessed. This means you can bind as early as you want, even in an
`init()` function.

For individual flags, the `BindPFlag()` method provides this functionality.

Example:

```go
serverCmd.Flags().Int("port", 1138, "Port to run Application server on")
viper.BindPFlag("port", serverCmd.Flags().Lookup("port"))
```

You can also bind an existing set of pflags (pflag.FlagSet):

Example:

```go
pflag.Int("flagname", 1234, "help message for flagname")

pflag.Parse()
viper.BindPFlags(pflag.CommandLine)

i := viper.GetInt("flagname") // retrieve values from viper instead of pflag
```

The use of [pflag](https://github.com/spf13/pflag/) in Viper does not preclude
the use of other packages that use the [flag](https://golang.org/pkg/flag/)
package from the standard library. The pflag package can handle the flags
defined for the flag package by importing these flags. This is accomplished
by a calling a convenience function provided by the pflag package called
AddGoFlagSet().

Example:

```go
package main

import (
	"flag"
	"github.com/spf13/pflag"
)

func main() {

	// using standard library "flag" package
	flag.Int("flagname", 1234, "help message for flagname")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	i := viper.GetInt("flagname") // retrieve value from viper

	...
}
```

#### Flag interfaces

Viper provides two Go interfaces to bind other flag systems if you don’t use `Pflags`.

`FlagValue` represents a single flag. This is a very simple example on how to implement this interface:

```go
type myFlag struct {}
func (f myFlag) HasChanged() bool { return false }
func (f myFlag) Name() string { return "my-flag-name" }
func (f myFlag) ValueString() string { return "my-flag-value" }
func (f myFlag) ValueType() string { return "string" }
```

Once your flag implements this interface, you can simply tell Viper to bind it:

```go
viper.BindFlagValue("my-flag-name", myFlag{})
```

`FlagValueSet` represents a group of flags. This is a very simple example on how to implement this interface:

```go
type myFlagSet struct {
	flags []myFlag
}

func (f myFlagSet) VisitAll(fn func(FlagValue)) {
	for _, flag := range flags {
		fn(flag)
	}
}
```

Once your flag set implements this interface, you can simply tell Viper to bind it:

```go
fSet := myFlagSet{
	flags: []myFlag{myFlag{}, myFlag{}},
}
viper.BindFlagValues("my-flags", fSet)
```

### Remote Key/Value Store Support

To enable remote support in Viper, do a blank import of the `viper/remote`
package:

`import _ "github.com/spf13/viper/remote"`

Viper will read a config string (as JSON, TOML, YAML or HCL) retrieved from a path
in a Key/Value store such as etcd or Consul.  These values take precedence over
default values, but are overridden by configuration values retrieved from disk,
flags, or environment variables.

Viper uses [crypt](https://github.com/xordataexchange/crypt) to retrieve
configuration from the K/V store, which means that you can store your
configuration values encrypted and have them automatically decrypted if you have
the correct gpg keyring.  Encryption is optional.

You can use remote configuration in conjunction with local configuration, or
independently of it.

`crypt` has a command-line helper that you can use to put configurations in your
K/V store. `crypt` defaults to etcd on http://127.0.0.1:4001.

```bash
$ go get github.com/xordataexchange/crypt/bin/crypt
$ crypt set -plaintext /config/hugo.json /Users/hugo/settings/config.json
```

Confirm that your value was set:

```bash
$ crypt get -plaintext /config/hugo.json
```

See the `crypt` documentation for examples of how to set encrypted values, or
how to use Consul.

### Remote Key/Value Store Example - Unencrypted

#### etcd
```go
viper.AddRemoteProvider("etcd", "http://127.0.0.1:4001","/config/hugo.json")
viper.SetConfigType("json") // because there is no file extension in a stream of bytes, supported extensions are "json", "toml", "yaml", "yml", "properties", "props", "prop"
err := viper.ReadRemoteConfig()
```

#### Consul
You need to set a key to Consul key/value storage with JSON value containing your desired config.  
For example, create a Consul key/value store key `MY_CONSUL_KEY` with value:

```json
{
    "port": 8080,
    "hostname": "myhostname.com"
}
```

```go
viper.AddRemoteProvider("consul", "localhost:8500", "MY_CONSUL_KEY")
viper.SetConfigType("json") // Need to explicitly set this to json
err := viper.ReadRemoteConfig()

fmt.Println(viper.Get("port")) // 8080
fmt.Println(viper.Get("hostname")) // myhostname.com
```

### Remote Key/Value Store Example - Encrypted

```go
viper.AddSecureRemoteProvider("etcd","http://127.0.0.1:4001","/config/hugo.json","/etc/secrets/mykeyring.gpg")
viper.SetConfigType("json") // because there is no file extension in a stream of bytes,  supported extensions are "json", "toml", "yaml", "yml", "properties", "props", "prop"
err := viper.ReadRemoteConfig()
```

### Watching Changes in etcd - Unencrypted

```go
// alternatively, you can create a new viper instance.
var runtime_viper = viper.New()

runtime_viper.AddRemoteProvider("etcd", "http://127.0.0.1:4001", "/config/hugo.yml")
runtime_viper.SetConfigType("yaml") // because there is no file extension in a stream of bytes, supported extensions are "json", "toml", "yaml", "yml", "properties", "props", "prop"

// read from remote config the first time.
err := runtime_viper.ReadRemoteConfig()

// unmarshal config
runtime_viper.Unmarshal(&runtime_conf)

// open a goroutine to watch remote changes forever
go func(){
	for {
	    time.Sleep(time.Second * 5) // delay after each request

	    // currently, only tested with etcd support
	    err := runtime_viper.WatchRemoteConfig()
	    if err != nil {
	        log.Errorf("unable to read remote config: %v", err)
	        continue
	    }

	    // unmarshal new config into our runtime config struct. you can also use channel
	    // to implement a signal to notify the system of the changes
	    runtime_viper.Unmarshal(&runtime_conf)
	}
}()
```

## Getting Values From Viper

In Viper, there are a few ways to get a value depending on the value’s type.
The following functions and methods exist:

 * `Get(key string) : interface{}`
 * `GetBool(key string) : bool`
 * `GetFloat64(key string) : float64`
 * `GetInt(key string) : int`
 * `GetString(key string) : string`
 * `GetStringMap(key string) : map[string]interface{}`
 * `GetStringMapString(key string) : map[string]string`
 * `GetStringSlice(key string) : []string`
 * `GetTime(key string) : time.Time`
 * `GetDuration(key string) : time.Duration`
 * `IsSet(key string) : bool`
 * `AllSettings() : map[string]interface{}`

One important thing to recognize is that each Get function will return a zero
value if it’s not found. To check if a given key exists, the `IsSet()` method
has been provided.

Example:
```go
viper.GetString("logfile") // case-insensitive Setting & Getting
if viper.GetBool("verbose") {
    fmt.Println("verbose enabled")
}
```
### Accessing nested keys

The accessor methods also accept formatted paths to deeply nested keys. For
example, if the following JSON file is loaded:

```json
{
    "host": {
        "address": "localhost",
        "port": 5799
    },
    "datastore": {
        "metric": {
            "host": "127.0.0.1",
            "port": 3099
        },
        "warehouse": {
            "host": "198.0.0.1",
            "port": 2112
        }
    }
}

```

Viper can access a nested field by passing a `.` delimited path of keys:

```go
GetString("datastore.metric.host") // (returns "127.0.0.1")
```

This obeys the precedence rules established above; the search for the path
will cascade through the remaining configuration registries until found.

For example, given this configuration file, both `datastore.metric.host` and
`datastore.metric.port` are already defined (and may be overridden). If in addition
`datastore.metric.protocol` was defined in the defaults, Viper would also find it.

However, if `datastore.metric` was overridden (by a flag, an environment variable,
the `Set()` method, …) with an immediate value, then all sub-keys of
`datastore.metric` become undefined, they are “shadowed” by the higher-priority
configuration level.

Lastly, if there exists a key that matches the delimited key path, its value
will be returned instead. E.g.

```json
{
    "datastore.metric.host": "0.0.0.0",
    "host": {
        "address": "localhost",
        "port": 5799
    },
    "datastore": {
        "metric": {
            "host": "127.0.0.1",
            "port": 3099
        },
        "warehouse": {
            "host": "198.0.0.1",
            "port": 2112
        }
    }
}

GetString("datastore.metric.host") // returns "0.0.0.0"
```

### Extract sub-tree

Extract sub-tree from Viper.

For example, `viper` represents:

```json
app:
  cache1:
    max-items: 100
    item-size: 64
  cache2:
    max-items: 200
    item-size: 80
```

After executing:

```go
subv := viper.Sub("app.cache1")
```

`subv` represents:

```json
max-items: 100
item-size: 64
```

Suppose we have:

```go
func NewCache(cfg *Viper) *Cache {...}
```

which creates a cache based on config information formatted as `subv`.
Now it’s easy to create these 2 caches separately as:

```go
cfg1 := viper.Sub("app.cache1")
cache1 := NewCache(cfg1)

cfg2 := viper.Sub("app.cache2")
cache2 := NewCache(cfg2)
```

### Unmarshaling

You also have the option of Unmarshaling all or a specific value to a struct, map,
etc.

There are two methods to do this:

 * `Unmarshal(rawVal interface{}) : error`
 * `UnmarshalKey(key string, rawVal interface{}) : error`

Example:

```go
type config struct {
	Port int
	Name string
	PathMap string `mapstructure:"path_map"`
}

var C config

err := Unmarshal(&C)
if err != nil {
	t.Fatalf("unable to decode into struct, %v", err)
}
```

### Marshalling to string

You may need to marhsal all the settings held in viper into a string rather than write them to a file. 
You can use your favorite format's marshaller with the config returned by `AllSettings()`.

```go
import (
    yaml "gopkg.in/yaml.v2"
    // ...
) 

func yamlStringSettings() string {
    c := viper.AllSettings()
	bs, err := yaml.Marshal(c)
	if err != nil {
        t.Fatalf("unable to marshal config to YAML: %v", err)
    }
	return string(bs)
}
```

## Viper or Vipers?

Viper comes ready to use out of the box. There is no configuration or
initialization needed to begin using Viper. Since most applications will want
to use a single central repository for their configuration, the viper package
provides this. It is similar to a singleton.

In all of the examples above, they demonstrate using viper in its singleton
style approach.

### Working with multiple vipers

You can also create many different vipers for use in your application. Each will
have its own unique set of configurations and values. Each can read from a
different config file, key value store, etc. All of the functions that viper
package supports are mirrored as methods on a viper.

Example:

```go
x := viper.New()
y := viper.New()

x.SetDefault("ContentDir", "content")
y.SetDefault("ContentDir", "foobar")

//...
```

When working with multiple vipers, it is up to the user to keep track of the
different vipers.

## Q & A

Q: Why not INI files?

A: Ini files are pretty awful. There’s no standard format, and they are hard to
validate. Viper is designed to work with JSON, TOML or YAML files. If someone
really wants to add this feature, I’d be happy to merge it. It’s easy to specify
which formats your application will permit.

Q: Why is it called “Viper”?

A: Viper is designed to be a [companion](http://en.wikipedia.org/wiki/Viper_(G.I._Joe))
to [Cobra](https://github.com/spf13/cobra). While both can operate completely
independently, together they make a powerful pair to handle much of your
application foundation needs.

Q: Why is it called “Cobra”?

A: Is there a better name for a [commander](http://en.wikipedia.org/wiki/Cobra_Commander)?
![afero logo-sm](https://cloud.githubusercontent.com/assets/173412/11490338/d50e16dc-97a5-11e5-8b12-019a300d0fcb.png)

A FileSystem Abstraction System for Go

[![Build Status](https://travis-ci.org/spf13/afero.svg)](https://travis-ci.org/spf13/afero) [![Build status](https://ci.appveyor.com/api/projects/status/github/spf13/afero?branch=master&svg=true)](https://ci.appveyor.com/project/spf13/afero) [![GoDoc](https://godoc.org/github.com/spf13/afero?status.svg)](https://godoc.org/github.com/spf13/afero) [![Join the chat at https://gitter.im/spf13/afero](https://badges.gitter.im/Dev%20Chat.svg)](https://gitter.im/spf13/afero?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

# Overview

Afero is an filesystem framework providing a simple, uniform and universal API
interacting with any filesystem, as an abstraction layer providing interfaces,
types and methods. Afero has an exceptionally clean interface and simple design
without needless constructors or initialization methods.

Afero is also a library providing a base set of interoperable backend
filesystems that make it easy to work with afero while retaining all the power
and benefit of the os and ioutil packages.

Afero provides significant improvements over using the os package alone, most
notably the ability to create mock and testing filesystems without relying on the disk.

It is suitable for use in a any situation where you would consider using the OS
package as it provides an additional abstraction that makes it easy to use a
memory backed file system during testing. It also adds support for the http
filesystem for full interoperability.


## Afero Features

* A single consistent API for accessing a variety of filesystems
* Interoperation between a variety of file system types
* A set of interfaces to encourage and enforce interoperability between backends
* An atomic cross platform memory backed file system
* Support for compositional (union) file systems by combining multiple file systems acting as one
* Specialized backends which modify existing filesystems (Read Only, Regexp filtered)
* A set of utility functions ported from io, ioutil & hugo to be afero aware


# Using Afero

Afero is easy to use and easier to adopt.

A few different ways you could use Afero:

* Use the interfaces alone to define you own file system.
* Wrap for the OS packages.
* Define different filesystems for different parts of your application.
* Use Afero for mock filesystems while testing

## Step 1: Install Afero

First use go get to install the latest version of the library.

    $ go get github.com/spf13/afero

Next include Afero in your application.
```go
import "github.com/spf13/afero"
```

## Step 2: Declare a backend

First define a package variable and set it to a pointer to a filesystem.
```go
var AppFs = afero.NewMemMapFs()

or

var AppFs = afero.NewOsFs()
```
It is important to note that if you repeat the composite literal you
will be using a completely new and isolated filesystem. In the case of
OsFs it will still use the same underlying filesystem but will reduce
the ability to drop in other filesystems as desired.

## Step 3: Use it like you would the OS package

Throughout your application use any function and method like you normally
would.

So if my application before had:
```go
os.Open('/tmp/foo')
```
We would replace it with:
```go
AppFs.Open('/tmp/foo')
```

`AppFs` being the variable we defined above.


## List of all available functions

File System Methods Available:
```go
Chmod(name string, mode os.FileMode) : error
Chtimes(name string, atime time.Time, mtime time.Time) : error
Create(name string) : File, error
Mkdir(name string, perm os.FileMode) : error
MkdirAll(path string, perm os.FileMode) : error
Name() : string
Open(name string) : File, error
OpenFile(name string, flag int, perm os.FileMode) : File, error
Remove(name string) : error
RemoveAll(path string) : error
Rename(oldname, newname string) : error
Stat(name string) : os.FileInfo, error
```
File Interfaces and Methods Available:
```go
io.Closer
io.Reader
io.ReaderAt
io.Seeker
io.Writer
io.WriterAt

Name() : string
Readdir(count int) : []os.FileInfo, error
Readdirnames(n int) : []string, error
Stat() : os.FileInfo, error
Sync() : error
Truncate(size int64) : error
WriteString(s string) : ret int, err error
```
In some applications it may make sense to define a new package that
simply exports the file system variable for easy access from anywhere.

## Using Afero's utility functions

Afero provides a set of functions to make it easier to use the underlying file systems.
These functions have been primarily ported from io & ioutil with some developed for Hugo.

The afero utilities support all afero compatible backends.

The list of utilities includes:

```go
DirExists(path string) (bool, error)
Exists(path string) (bool, error)
FileContainsBytes(filename string, subslice []byte) (bool, error)
GetTempDir(subPath string) string
IsDir(path string) (bool, error)
IsEmpty(path string) (bool, error)
ReadDir(dirname string) ([]os.FileInfo, error)
ReadFile(filename string) ([]byte, error)
SafeWriteReader(path string, r io.Reader) (err error)
TempDir(dir, prefix string) (name string, err error)
TempFile(dir, prefix string) (f File, err error)
Walk(root string, walkFn filepath.WalkFunc) error
WriteFile(filename string, data []byte, perm os.FileMode) error
WriteReader(path string, r io.Reader) (err error)
```
For a complete list see [Afero's GoDoc](https://godoc.org/github.com/spf13/afero)

They are available under two different approaches to use. You can either call
them directly where the first parameter of each function will be the file
system, or you can declare a new `Afero`, a custom type used to bind these
functions as methods to a given filesystem.

### Calling utilities directly

```go
fs := new(afero.MemMapFs)
f, err := afero.TempFile(fs,"", "ioutil-test")

```

### Calling via Afero

```go
fs := afero.NewMemMapFs()
afs := &afero.Afero{Fs: fs}
f, err := afs.TempFile("", "ioutil-test")
```

## Using Afero for Testing

There is a large benefit to using a mock filesystem for testing. It has a
completely blank state every time it is initialized and can be easily
reproducible regardless of OS. You could create files to your heart’s content
and the file access would be fast while also saving you from all the annoying
issues with deleting temporary files, Windows file locking, etc. The MemMapFs
backend is perfect for testing.

* Much faster than performing I/O operations on disk
* Avoid security issues and permissions
* Far more control. 'rm -rf /' with confidence
* Test setup is far more easier to do
* No test cleanup needed

One way to accomplish this is to define a variable as mentioned above.
In your application this will be set to afero.NewOsFs() during testing you
can set it to afero.NewMemMapFs().

It wouldn't be uncommon to have each test initialize a blank slate memory
backend. To do this I would define my `appFS = afero.NewOsFs()` somewhere
appropriate in my application code. This approach ensures that Tests are order
independent, with no test relying on the state left by an earlier test.

Then in my tests I would initialize a new MemMapFs for each test:
```go
func TestExist(t *testing.T) {
	appFS := afero.NewMemMapFs()
	// create test files and directories
	appFS.MkdirAll("src/a", 0755)
	afero.WriteFile(appFS, "src/a/b", []byte("file b"), 0644)
	afero.WriteFile(appFS, "src/c", []byte("file c"), 0644)
	name := "src/c"
	_, err := appFS.Stat(name)
	if os.IsNotExist(err) {
		t.Errorf("file \"%s\" does not exist.\n", name)
	}
}
```

# Available Backends

## Operating System Native

### OsFs

The first is simply a wrapper around the native OS calls. This makes it
very easy to use as all of the calls are the same as the existing OS
calls. It also makes it trivial to have your code use the OS during
operation and a mock filesystem during testing or as needed.

```go
appfs := afero.NewOsFs()
appfs.MkdirAll("src/a", 0755))
```

## Memory Backed Storage

### MemMapFs

Afero also provides a fully atomic memory backed filesystem perfect for use in
mocking and to speed up unnecessary disk io when persistence isn’t
necessary. It is fully concurrent and will work within go routines
safely.

```go
mm := afero.NewMemMapFs()
mm.MkdirAll("src/a", 0755))
```

#### InMemoryFile

As part of MemMapFs, Afero also provides an atomic, fully concurrent memory
backed file implementation. This can be used in other memory backed file
systems with ease. Plans are to add a radix tree memory stored file
system using InMemoryFile.

## Network Interfaces

### SftpFs

Afero has experimental support for secure file transfer protocol (sftp). Which can
be used to perform file operations over a encrypted channel.

## Filtering Backends

### BasePathFs

The BasePathFs restricts all operations to a given path within an Fs.
The given file name to the operations on this Fs will be prepended with
the base path before calling the source Fs.

```go
bp := afero.NewBasePathFs(afero.NewOsFs(), "/base/path")
```

### ReadOnlyFs

A thin wrapper around the source Fs providing a read only view.

```go
fs := afero.NewReadOnlyFs(afero.NewOsFs())
_, err := fs.Create("/file.txt")
// err = syscall.EPERM
```

# RegexpFs

A filtered view on file names, any file NOT matching
the passed regexp will be treated as non-existing.
Files not matching the regexp provided will not be created.
Directories are not filtered.

```go
fs := afero.NewRegexpFs(afero.NewMemMapFs(), regexp.MustCompile(`\.txt$`))
_, err := fs.Create("/file.html")
// err = syscall.ENOENT
```

### HttpFs

Afero provides an http compatible backend which can wrap any of the existing
backends.

The Http package requires a slightly specific version of Open which
returns an http.File type.

Afero provides an httpFs file system which satisfies this requirement.
Any Afero FileSystem can be used as an httpFs.

```go
httpFs := afero.NewHttpFs(<ExistingFS>)
fileserver := http.FileServer(httpFs.Dir(<PATH>)))
http.Handle("/", fileserver)
```

## Composite Backends

Afero provides the ability have two filesystems (or more) act as a single
file system.

### CacheOnReadFs

The CacheOnReadFs will lazily make copies of any accessed files from the base
layer into the overlay. Subsequent reads will be pulled from the overlay
directly permitting the request is within the cache duration of when it was
created in the overlay.

If the base filesystem is writeable, any changes to files will be
done first to the base, then to the overlay layer. Write calls to open file
handles like `Write()` or `Truncate()` to the overlay first.

To writing files to the overlay only, you can use the overlay Fs directly (not
via the union Fs).

Cache files in the layer for the given time.Duration, a cache duration of 0
means "forever" meaning the file will not be re-requested from the base ever.

A read-only base will make the overlay also read-only but still copy files
from the base to the overlay when they're not present (or outdated) in the
caching layer.

```go
base := afero.NewOsFs()
layer := afero.NewMemMapFs()
ufs := afero.NewCacheOnReadFs(base, layer, 100 * time.Second)
```

### CopyOnWriteFs()

The CopyOnWriteFs is a read only base file system with a potentially
writeable layer on top.

Read operations will first look in the overlay and if not found there, will
serve the file from the base.

Changes to the file system will only be made in the overlay.

Any attempt to modify a file found only in the base will copy the file to the
overlay layer before modification (including opening a file with a writable
handle).

Removing and Renaming files present only in the base layer is not currently
permitted. If a file is present in the base layer and the overlay, only the
overlay will be removed/renamed.

```go
	base := afero.NewOsFs()
	roBase := afero.NewReadOnlyFs(base)
	ufs := afero.NewCopyOnWriteFs(roBase, afero.NewMemMapFs())

	fh, _ = ufs.Create("/home/test/file2.txt")
	fh.WriteString("This is a test")
	fh.Close()
```

In this example all write operations will only occur in memory (MemMapFs)
leaving the base filesystem (OsFs) untouched.


## Desired/possible backends

The following is a short list of possible backends we hope someone will
implement:

* SSH
* ZIP
* TAR
* S3

# About the project

## What's in the name

Afero comes from the latin roots Ad-Facere.

**"Ad"** is a prefix meaning "to".

**"Facere"** is a form of the root "faciō" making "make or do".

The literal meaning of afero is "to make" or "to do" which seems very fitting
for a library that allows one to make files and directories and do things with them.

The English word that shares the same roots as Afero is "affair". Affair shares
the same concept but as a noun it means "something that is made or done" or "an
object of a particular type".

It's also nice that unlike some of my other libraries (hugo, cobra, viper) it
Googles very well.

## Release Notes

* **0.10.0** 2015.12.10
  * Full compatibility with Windows
  * Introduction of afero utilities
  * Test suite rewritten to work cross platform
  * Normalize paths for MemMapFs
  * Adding Sync to the file interface
  * **Breaking Change** Walk and ReadDir have changed parameter order
  * Moving types used by MemMapFs to a subpackage
  * General bugfixes and improvements
* **0.9.0** 2015.11.05
  * New Walk function similar to filepath.Walk
  * MemMapFs.OpenFile handles O_CREATE, O_APPEND, O_TRUNC
  * MemMapFs.Remove now really deletes the file
  * InMemoryFile.Readdir and Readdirnames work correctly
  * InMemoryFile functions lock it for concurrent access
  * Test suite improvements
* **0.8.0** 2014.10.28
  * First public version
  * Interfaces feel ready for people to build using
  * Interfaces satisfy all known uses
  * MemMapFs passes the majority of the OS test suite
  * OsFs passes the majority of the OS test suite

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## Contributors

Names in no particular order:

* [spf13](https://github.com/spf13)
* [jaqx0r](https://github.com/jaqx0r)
* [mbertschler](https://github.com/mbertschler)
* [xor-gate](https://github.com/xor-gate)

## License

Afero is released under the Apache 2.0 license. See
[LICENSE.txt](https://github.com/spf13/afero/blob/master/LICENSE.txt)
cast
====
[![GoDoc](https://godoc.org/github.com/spf13/cast?status.svg)](https://godoc.org/github.com/spf13/cast)
[![Build Status](https://api.travis-ci.org/spf13/cast.svg?branch=master)](https://travis-ci.org/spf13/cast)
[![Go Report Card](https://goreportcard.com/badge/github.com/spf13/cast)](https://goreportcard.com/report/github.com/spf13/cast)

Easy and safe casting from one type to another in Go

Don’t Panic! ... Cast

## What is Cast?

Cast is a library to convert between different go types in a consistent and easy way.

Cast provides simple functions to easily convert a number to a string, an
interface into a bool, etc. Cast does this intelligently when an obvious
conversion is possible. It doesn’t make any attempts to guess what you meant,
for example you can only convert a string to an int when it is a string
representation of an int such as “8”. Cast was developed for use in
[Hugo](http://hugo.spf13.com), a website engine which uses YAML, TOML or JSON
for meta data.

## Why use Cast?

When working with dynamic data in Go you often need to cast or convert the data
from one type into another. Cast goes beyond just using type assertion (though
it uses that when possible) to provide a very straightforward and convenient
library.

If you are working with interfaces to handle things like dynamic content
you’ll need an easy way to convert an interface into a given type. This
is the library for you.

If you are taking in data from YAML, TOML or JSON or other formats which lack
full types, then Cast is the library for you.

## Usage

Cast provides a handful of To_____ methods. These methods will always return
the desired type. **If input is provided that will not convert to that type, the
0 or nil value for that type will be returned**.

Cast also provides identical methods To_____E. These return the same result as
the To_____ methods, plus an additional error which tells you if it successfully
converted. Using these methods you can tell the difference between when the
input matched the zero value or when the conversion failed and the zero value
was returned.

The following examples are merely a sample of what is available. Please review
the code for a complete set.

### Example ‘ToString’:

    cast.ToString("mayonegg")         // "mayonegg"
    cast.ToString(8)                  // "8"
    cast.ToString(8.31)               // "8.31"
    cast.ToString([]byte("one time")) // "one time"
    cast.ToString(nil)                // ""

	var foo interface{} = "one more time"
    cast.ToString(foo)                // "one more time"


### Example ‘ToInt’:

    cast.ToInt(8)                  // 8
    cast.ToInt(8.31)               // 8
    cast.ToInt("8")                // 8
    cast.ToInt(true)               // 1
    cast.ToInt(false)              // 0

	var eight interface{} = 8
    cast.ToInt(eight)              // 8
    cast.ToInt(nil)                // 0

# gorilla/mux

[![GoDoc](https://godoc.org/github.com/gorilla/mux?status.svg)](https://godoc.org/github.com/gorilla/mux)
[![Build Status](https://travis-ci.org/gorilla/mux.svg?branch=master)](https://travis-ci.org/gorilla/mux)
[![CircleCI](https://circleci.com/gh/gorilla/mux.svg?style=svg)](https://circleci.com/gh/gorilla/mux)
[![Sourcegraph](https://sourcegraph.com/github.com/gorilla/mux/-/badge.svg)](https://sourcegraph.com/github.com/gorilla/mux?badge)

![Gorilla Logo](http://www.gorillatoolkit.org/static/images/gorilla-icon-64.png)

https://www.gorillatoolkit.org/pkg/mux

Package `gorilla/mux` implements a request router and dispatcher for matching incoming requests to
their respective handler.

The name mux stands for "HTTP request multiplexer". Like the standard `http.ServeMux`, `mux.Router` matches incoming requests against a list of registered routes and calls a handler for the route that matches the URL or other conditions. The main features are:

* It implements the `http.Handler` interface so it is compatible with the standard `http.ServeMux`.
* Requests can be matched based on URL host, path, path prefix, schemes, header and query values, HTTP methods or using custom matchers.
* URL hosts, paths and query values can have variables with an optional regular expression.
* Registered URLs can be built, or "reversed", which helps maintaining references to resources.
* Routes can be used as subrouters: nested routes are only tested if the parent route matches. This is useful to define groups of routes that share common conditions like a host, a path prefix or other repeated attributes. As a bonus, this optimizes request matching.

---

* [Install](#install)
* [Examples](#examples)
* [Matching Routes](#matching-routes)
* [Static Files](#static-files)
* [Registered URLs](#registered-urls)
* [Walking Routes](#walking-routes)
* [Graceful Shutdown](#graceful-shutdown)
* [Middleware](#middleware)
* [Handling CORS Requests](#handling-cors-requests)
* [Testing Handlers](#testing-handlers)
* [Full Example](#full-example)

---

## Install

With a [correctly configured](https://golang.org/doc/install#testing) Go toolchain:

```sh
go get -u github.com/gorilla/mux
```

## Examples

Let's start registering a couple of URL paths and handlers:

```go
func main() {
    r := mux.NewRouter()
    r.HandleFunc("/", HomeHandler)
    r.HandleFunc("/products", ProductsHandler)
    r.HandleFunc("/articles", ArticlesHandler)
    http.Handle("/", r)
}
```

Here we register three routes mapping URL paths to handlers. This is equivalent to how `http.HandleFunc()` works: if an incoming request URL matches one of the paths, the corresponding handler is called passing (`http.ResponseWriter`, `*http.Request`) as parameters.

Paths can have variables. They are defined using the format `{name}` or `{name:pattern}`. If a regular expression pattern is not defined, the matched variable will be anything until the next slash. For example:

```go
r := mux.NewRouter()
r.HandleFunc("/products/{key}", ProductHandler)
r.HandleFunc("/articles/{category}/", ArticlesCategoryHandler)
r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler)
```

The names are used to create a map of route variables which can be retrieved calling `mux.Vars()`:

```go
func ArticlesCategoryHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "Category: %v\n", vars["category"])
}
```

And this is all you need to know about the basic usage. More advanced options are explained below.

### Matching Routes

Routes can also be restricted to a domain or subdomain. Just define a host pattern to be matched. They can also have variables:

```go
r := mux.NewRouter()
// Only matches if domain is "www.example.com".
r.Host("www.example.com")
// Matches a dynamic subdomain.
r.Host("{subdomain:[a-z]+}.example.com")
```

There are several other matchers that can be added. To match path prefixes:

```go
r.PathPrefix("/products/")
```

...or HTTP methods:

```go
r.Methods("GET", "POST")
```

...or URL schemes:

```go
r.Schemes("https")
```

...or header values:

```go
r.Headers("X-Requested-With", "XMLHttpRequest")
```

...or query values:

```go
r.Queries("key", "value")
```

...or to use a custom matcher function:

```go
r.MatcherFunc(func(r *http.Request, rm *RouteMatch) bool {
    return r.ProtoMajor == 0
})
```

...and finally, it is possible to combine several matchers in a single route:

```go
r.HandleFunc("/products", ProductsHandler).
  Host("www.example.com").
  Methods("GET").
  Schemes("http")
```

Routes are tested in the order they were added to the router. If two routes match, the first one wins:

```go
r := mux.NewRouter()
r.HandleFunc("/specific", specificHandler)
r.PathPrefix("/").Handler(catchAllHandler)
```

Setting the same matching conditions again and again can be boring, so we have a way to group several routes that share the same requirements. We call it "subrouting".

For example, let's say we have several URLs that should only match when the host is `www.example.com`. Create a route for that host and get a "subrouter" from it:

```go
r := mux.NewRouter()
s := r.Host("www.example.com").Subrouter()
```

Then register routes in the subrouter:

```go
s.HandleFunc("/products/", ProductsHandler)
s.HandleFunc("/products/{key}", ProductHandler)
s.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler)
```

The three URL paths we registered above will only be tested if the domain is `www.example.com`, because the subrouter is tested first. This is not only convenient, but also optimizes request matching. You can create subrouters combining any attribute matchers accepted by a route.

Subrouters can be used to create domain or path "namespaces": you define subrouters in a central place and then parts of the app can register its paths relatively to a given subrouter.

There's one more thing about subroutes. When a subrouter has a path prefix, the inner routes use it as base for their paths:

```go
r := mux.NewRouter()
s := r.PathPrefix("/products").Subrouter()
// "/products/"
s.HandleFunc("/", ProductsHandler)
// "/products/{key}/"
s.HandleFunc("/{key}/", ProductHandler)
// "/products/{key}/details"
s.HandleFunc("/{key}/details", ProductDetailsHandler)
```


### Static Files

Note that the path provided to `PathPrefix()` represents a "wildcard": calling
`PathPrefix("/static/").Handler(...)` means that the handler will be passed any
request that matches "/static/\*". This makes it easy to serve static files with mux:

```go
func main() {
    var dir string

    flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
    flag.Parse()
    r := mux.NewRouter()

    // This will serve files under http://localhost:8000/static/<filename>
    r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(dir))))

    srv := &http.Server{
        Handler:      r,
        Addr:         "127.0.0.1:8000",
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }

    log.Fatal(srv.ListenAndServe())
}
```

### Registered URLs

Now let's see how to build registered URLs.

Routes can be named. All routes that define a name can have their URLs built, or "reversed". We define a name calling `Name()` on a route. For example:

```go
r := mux.NewRouter()
r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).
  Name("article")
```

To build a URL, get the route and call the `URL()` method, passing a sequence of key/value pairs for the route variables. For the previous route, we would do:

```go
url, err := r.Get("article").URL("category", "technology", "id", "42")
```

...and the result will be a `url.URL` with the following path:

```
"/articles/technology/42"
```

This also works for host and query value variables:

```go
r := mux.NewRouter()
r.Host("{subdomain}.example.com").
  Path("/articles/{category}/{id:[0-9]+}").
  Queries("filter", "{filter}").
  HandlerFunc(ArticleHandler).
  Name("article")

// url.String() will be "http://news.example.com/articles/technology/42?filter=gorilla"
url, err := r.Get("article").URL("subdomain", "news",
                                 "category", "technology",
                                 "id", "42",
                                 "filter", "gorilla")
```

All variables defined in the route are required, and their values must conform to the corresponding patterns. These requirements guarantee that a generated URL will always match a registered route -- the only exception is for explicitly defined "build-only" routes which never match.

Regex support also exists for matching Headers within a route. For example, we could do:

```go
r.HeadersRegexp("Content-Type", "application/(text|json)")
```

...and the route will match both requests with a Content-Type of `application/json` as well as `application/text`

There's also a way to build only the URL host or path for a route: use the methods `URLHost()` or `URLPath()` instead. For the previous route, we would do:

```go
// "http://news.example.com/"
host, err := r.Get("article").URLHost("subdomain", "news")

// "/articles/technology/42"
path, err := r.Get("article").URLPath("category", "technology", "id", "42")
```

And if you use subrouters, host and path defined separately can be built as well:

```go
r := mux.NewRouter()
s := r.Host("{subdomain}.example.com").Subrouter()
s.Path("/articles/{category}/{id:[0-9]+}").
  HandlerFunc(ArticleHandler).
  Name("article")

// "http://news.example.com/articles/technology/42"
url, err := r.Get("article").URL("subdomain", "news",
                                 "category", "technology",
                                 "id", "42")
```

### Walking Routes

The `Walk` function on `mux.Router` can be used to visit all of the routes that are registered on a router. For example,
the following prints all of the registered routes:

```go
package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

func handler(w http.ResponseWriter, r *http.Request) {
	return
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", handler)
	r.HandleFunc("/products", handler).Methods("POST")
	r.HandleFunc("/articles", handler).Methods("GET")
	r.HandleFunc("/articles/{id}", handler).Methods("GET", "PUT")
	r.HandleFunc("/authors", handler).Queries("surname", "{surname}")
	err := r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, err := route.GetPathTemplate()
		if err == nil {
			fmt.Println("ROUTE:", pathTemplate)
		}
		pathRegexp, err := route.GetPathRegexp()
		if err == nil {
			fmt.Println("Path regexp:", pathRegexp)
		}
		queriesTemplates, err := route.GetQueriesTemplates()
		if err == nil {
			fmt.Println("Queries templates:", strings.Join(queriesTemplates, ","))
		}
		queriesRegexps, err := route.GetQueriesRegexp()
		if err == nil {
			fmt.Println("Queries regexps:", strings.Join(queriesRegexps, ","))
		}
		methods, err := route.GetMethods()
		if err == nil {
			fmt.Println("Methods:", strings.Join(methods, ","))
		}
		fmt.Println()
		return nil
	})

	if err != nil {
		fmt.Println(err)
	}

	http.Handle("/", r)
}
```

### Graceful Shutdown

Go 1.8 introduced the ability to [gracefully shutdown](https://golang.org/doc/go1.8#http_shutdown) a `*http.Server`. Here's how to do that alongside `mux`:

```go
package main

import (
    "context"
    "flag"
    "log"
    "net/http"
    "os"
    "os/signal"
    "time"

    "github.com/gorilla/mux"
)

func main() {
    var wait time.Duration
    flag.DurationVar(&wait, "graceful-timeout", time.Second * 15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
    flag.Parse()

    r := mux.NewRouter()
    // Add your routes as needed

    srv := &http.Server{
        Addr:         "0.0.0.0:8080",
        // Good practice to set timeouts to avoid Slowloris attacks.
        WriteTimeout: time.Second * 15,
        ReadTimeout:  time.Second * 15,
        IdleTimeout:  time.Second * 60,
        Handler: r, // Pass our instance of gorilla/mux in.
    }

    // Run our server in a goroutine so that it doesn't block.
    go func() {
        if err := srv.ListenAndServe(); err != nil {
            log.Println(err)
        }
    }()

    c := make(chan os.Signal, 1)
    // We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
    // SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
    signal.Notify(c, os.Interrupt)

    // Block until we receive our signal.
    <-c

    // Create a deadline to wait for.
    ctx, cancel := context.WithTimeout(context.Background(), wait)
    defer cancel()
    // Doesn't block if no connections, but will otherwise wait
    // until the timeout deadline.
    srv.Shutdown(ctx)
    // Optionally, you could run srv.Shutdown in a goroutine and block on
    // <-ctx.Done() if your application should wait for other services
    // to finalize based on context cancellation.
    log.Println("shutting down")
    os.Exit(0)
}
```

### Middleware

Mux supports the addition of middlewares to a [Router](https://godoc.org/github.com/gorilla/mux#Router), which are executed in the order they are added if a match is found, including its subrouters.
Middlewares are (typically) small pieces of code which take one request, do something with it, and pass it down to another middleware or the final handler. Some common use cases for middleware are request logging, header manipulation, or `ResponseWriter` hijacking.

Mux middlewares are defined using the de facto standard type:

```go
type MiddlewareFunc func(http.Handler) http.Handler
```

Typically, the returned handler is a closure which does something with the http.ResponseWriter and http.Request passed to it, and then calls the handler passed as parameter to the MiddlewareFunc. This takes advantage of closures being able access variables from the context where they are created, while retaining the signature enforced by the receivers.

A very basic middleware which logs the URI of the request being handled could be written as:

```go
func loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Do stuff here
        log.Println(r.RequestURI)
        // Call the next handler, which can be another middleware in the chain, or the final handler.
        next.ServeHTTP(w, r)
    })
}
```

Middlewares can be added to a router using `Router.Use()`:

```go
r := mux.NewRouter()
r.HandleFunc("/", handler)
r.Use(loggingMiddleware)
```

A more complex authentication middleware, which maps session token to users, could be written as:

```go
// Define our struct
type authenticationMiddleware struct {
	tokenUsers map[string]string
}

// Initialize it somewhere
func (amw *authenticationMiddleware) Populate() {
	amw.tokenUsers["00000000"] = "user0"
	amw.tokenUsers["aaaaaaaa"] = "userA"
	amw.tokenUsers["05f717e5"] = "randomUser"
	amw.tokenUsers["deadbeef"] = "user0"
}

// Middleware function, which will be called for each request
func (amw *authenticationMiddleware) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("X-Session-Token")

        if user, found := amw.tokenUsers[token]; found {
        	// We found the token in our map
        	log.Printf("Authenticated user %s\n", user)
        	// Pass down the request to the next middleware (or final handler)
        	next.ServeHTTP(w, r)
        } else {
        	// Write an error and stop the handler chain
        	http.Error(w, "Forbidden", http.StatusForbidden)
        }
    })
}
```

```go
r := mux.NewRouter()
r.HandleFunc("/", handler)

amw := authenticationMiddleware{}
amw.Populate()

r.Use(amw.Middleware)
```

Note: The handler chain will be stopped if your middleware doesn't call `next.ServeHTTP()` with the corresponding parameters. This can be used to abort a request if the middleware writer wants to. Middlewares _should_ write to `ResponseWriter` if they _are_ going to terminate the request, and they _should not_ write to `ResponseWriter` if they _are not_ going to terminate it.

### Handling CORS Requests

[CORSMethodMiddleware](https://godoc.org/github.com/gorilla/mux#CORSMethodMiddleware) intends to make it easier to strictly set the `Access-Control-Allow-Methods` response header.

* You will still need to use your own CORS handler to set the other CORS headers such as `Access-Control-Allow-Origin`
* The middleware will set the `Access-Control-Allow-Methods` header to all the method matchers (e.g. `r.Methods(http.MethodGet, http.MethodPut, http.MethodOptions)` -> `Access-Control-Allow-Methods: GET,PUT,OPTIONS`) on a route
* If you do not specify any methods, then:
> _Important_: there must be an `OPTIONS` method matcher for the middleware to set the headers.

Here is an example of using `CORSMethodMiddleware` along with a custom `OPTIONS` handler to set all the required CORS headers:

```go
package main

import (
	"net/http"
	"github.com/gorilla/mux"
)

func main() {
    r := mux.NewRouter()

    // IMPORTANT: you must specify an OPTIONS method matcher for the middleware to set CORS headers
    r.HandleFunc("/foo", fooHandler).Methods(http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodOptions)
    r.Use(mux.CORSMethodMiddleware(r))
    
    http.ListenAndServe(":8080", r)
}

func fooHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    if r.Method == http.MethodOptions {
        return
    }

    w.Write([]byte("foo"))
}
```

And an request to `/foo` using something like:

```bash
curl localhost:8080/foo -v
```

Would look like:

```bash
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
> GET /foo HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.59.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Access-Control-Allow-Methods: GET,PUT,PATCH,OPTIONS
< Access-Control-Allow-Origin: *
< Date: Fri, 28 Jun 2019 20:13:30 GMT
< Content-Length: 3
< Content-Type: text/plain; charset=utf-8
< 
* Connection #0 to host localhost left intact
foo
```

### Testing Handlers

Testing handlers in a Go web application is straightforward, and _mux_ doesn't complicate this any further. Given two files: `endpoints.go` and `endpoints_test.go`, here's how we'd test an application using _mux_.

First, our simple HTTP handler:

```go
// endpoints.go
package main

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
    // A very simple health check.
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)

    // In the future we could report back on the status of our DB, or our cache
    // (e.g. Redis) by performing a simple PING, and include them in the response.
    io.WriteString(w, `{"alive": true}`)
}

func main() {
    r := mux.NewRouter()
    r.HandleFunc("/health", HealthCheckHandler)

    log.Fatal(http.ListenAndServe("localhost:8080", r))
}
```

Our test code:

```go
// endpoints_test.go
package main

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestHealthCheckHandler(t *testing.T) {
    // Create a request to pass to our handler. We don't have any query parameters for now, so we'll
    // pass 'nil' as the third parameter.
    req, err := http.NewRequest("GET", "/health", nil)
    if err != nil {
        t.Fatal(err)
    }

    // We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(HealthCheckHandler)

    // Our handlers satisfy http.Handler, so we can call their ServeHTTP method
    // directly and pass in our Request and ResponseRecorder.
    handler.ServeHTTP(rr, req)

    // Check the status code is what we expect.
    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v",
            status, http.StatusOK)
    }

    // Check the response body is what we expect.
    expected := `{"alive": true}`
    if rr.Body.String() != expected {
        t.Errorf("handler returned unexpected body: got %v want %v",
            rr.Body.String(), expected)
    }
}
```

In the case that our routes have [variables](#examples), we can pass those in the request. We could write
[table-driven tests](https://dave.cheney.net/2013/06/09/writing-table-driven-tests-in-go) to test multiple
possible route variables as needed.

```go
// endpoints.go
func main() {
    r := mux.NewRouter()
    // A route with a route variable:
    r.HandleFunc("/metrics/{type}", MetricsHandler)

    log.Fatal(http.ListenAndServe("localhost:8080", r))
}
```

Our test file, with a table-driven test of `routeVariables`:

```go
// endpoints_test.go
func TestMetricsHandler(t *testing.T) {
    tt := []struct{
        routeVariable string
        shouldPass bool
    }{
        {"goroutines", true},
        {"heap", true},
        {"counters", true},
        {"queries", true},
        {"adhadaeqm3k", false},
    }

    for _, tc := range tt {
        path := fmt.Sprintf("/metrics/%s", tc.routeVariable)
        req, err := http.NewRequest("GET", path, nil)
        if err != nil {
            t.Fatal(err)
        }

        rr := httptest.NewRecorder()
	
	// Need to create a router that we can pass the request through so that the vars will be added to the context
	router := mux.NewRouter()
        router.HandleFunc("/metrics/{type}", MetricsHandler)
        router.ServeHTTP(rr, req)

        // In this case, our MetricsHandler returns a non-200 response
        // for a route variable it doesn't know about.
        if rr.Code == http.StatusOK && !tc.shouldPass {
            t.Errorf("handler should have failed on routeVariable %s: got %v want %v",
                tc.routeVariable, rr.Code, http.StatusOK)
        }
    }
}
```

## Full Example

Here's a complete, runnable example of a small `mux` based server:

```go
package main

import (
    "net/http"
    "log"
    "github.com/gorilla/mux"
)

func YourHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Gorilla!\n"))
}

func main() {
    r := mux.NewRouter()
    // Routes consist of a path and a handler function.
    r.HandleFunc("/", YourHandler)

    // Bind to a port and pass our router in
    log.Fatal(http.ListenAndServe(":8000", r))
}
```

## License

BSD licensed. See the LICENSE file for details.
# HTTP CONNECT tunneling Go Dialer

[![Travis Build](https://travis-ci.org/mwitkow/go-http-dialer.svg)](https://travis-ci.org/mwitkow/go-http-dialer)
[![Go Report Card](https://goreportcard.com/badge/github.com/mwitkow/go-http-dialer)](http://goreportcard.com/report/mwitkow/go-http-dialer)
[![GoDoc](http://img.shields.io/badge/GoDoc-Reference-blue.svg)](https://godoc.org/github.com/mwitkow/go-http-dialer)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A `net.Dialer` drop-in that establishes the TCP connection over an [HTTP CONNECT Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel#HTTP_CONNECT_tunneling).

## Why?!

Some enterprises have fairly restrictive networking environments. They typically operate [HTTP forward proxies](https://en.wikipedia.org/wiki/Proxy_server) that require user authentication. These proxies usually allow  HTTPS (TCP to `:443`) to pass through the proxy using the [`CONNECT`](https://tools.ietf.org/html/rfc2616#section-9.9) method. The `CONNECT` method is basically a HTTP-negotiated "end-to-end" TCP stream... which is exactly what [`net.Conn`](https://golang.org/pkg/net/#Conn) is :)

## But, really, why?

Because if you want to call [gRPC](http://www.grpc.io/) services which are exposed publicly over `:443` TLS over an HTTP proxy, you can't.

Also, this allows you to call any TCP service over HTTP `CONNECT`... if your proxy allows you to `¯\(ツ)/¯`

## Supported features

 - [x] unencrypted connection to proxy (e.g. `http://proxy.example.com:3128`
 - [x] TLS connection to proxy (customizeable) (e.g. `https://proxy.example.com`)
 - [x] customizeable for `Proxy-Authenticate`, with challenge-response semantics
 - [x] out of the box support for `Basic` auth
 - [ ] appropriate `RemoteAddr` remapping
 

## Usage with gRPC



## License

`go-http-dialer` is released under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
# mapstructure [![Godoc](https://godoc.org/github.com/mitchellh/mapstructure?status.svg)](https://godoc.org/github.com/mitchellh/mapstructure)

mapstructure is a Go library for decoding generic map values to structures
and vice versa, while providing helpful error handling.

This library is most useful when decoding values from some data stream (JSON,
Gob, etc.) where you don't _quite_ know the structure of the underlying data
until you read a part of it. You can therefore read a `map[string]interface{}`
and use this library to decode it into the proper underlying native Go
structure.

## Installation

Standard `go get`:

```
$ go get github.com/mitchellh/mapstructure
```

## Usage & Example

For usage and examples see the [Godoc](http://godoc.org/github.com/mitchellh/mapstructure).

The `Decode` function has examples associated with it there.

## But Why?!

Go offers fantastic standard libraries for decoding formats such as JSON.
The standard method is to have a struct pre-created, and populate that struct
from the bytes of the encoded format. This is great, but the problem is if
you have configuration or an encoding that changes slightly depending on
specific fields. For example, consider this JSON:

```json
{
  "type": "person",
  "name": "Mitchell"
}
```

Perhaps we can't populate a specific structure without first reading
the "type" field from the JSON. We could always do two passes over the
decoding of the JSON (reading the "type" first, and the rest later).
However, it is much simpler to just decode this into a `map[string]interface{}`
structure, read the "type" key, then use something like this library
to decode it into the proper structure.
[![Build Status](https://travis-ci.org/chzyer/readline.svg?branch=master)](https://travis-ci.org/chzyer/readline)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE.md)
[![Version](https://img.shields.io/github/tag/chzyer/readline.svg)](https://github.com/chzyer/readline/releases)
[![GoDoc](https://godoc.org/github.com/chzyer/readline?status.svg)](https://godoc.org/github.com/chzyer/readline)
[![OpenCollective](https://opencollective.com/readline/badge/backers.svg)](#backers)
[![OpenCollective](https://opencollective.com/readline/badge/sponsors.svg)](#sponsors)

<p align="center">
<img src="https://raw.githubusercontent.com/chzyer/readline/assets/logo.png" />
<a href="https://asciinema.org/a/32oseof9mkilg7t7d4780qt4m" target="_blank"><img src="https://asciinema.org/a/32oseof9mkilg7t7d4780qt4m.png" width="654"/></a>
<img src="https://raw.githubusercontent.com/chzyer/readline/assets/logo_f.png" />
</p>

A powerful readline library in `Linux` `macOS` `Windows` `Solaris`

## Guide

* [Demo](example/readline-demo/readline-demo.go)
* [Shortcut](doc/shortcut.md)

## Repos using readline

[![cockroachdb](https://img.shields.io/github/stars/cockroachdb/cockroach.svg?label=cockroachdb/cockroach)](https://github.com/cockroachdb/cockroach)
[![robertkrimen/otto](https://img.shields.io/github/stars/robertkrimen/otto.svg?label=robertkrimen/otto)](https://github.com/robertkrimen/otto)
[![empire](https://img.shields.io/github/stars/remind101/empire.svg?label=remind101/empire)](https://github.com/remind101/empire)
[![mehrdadrad/mylg](https://img.shields.io/github/stars/mehrdadrad/mylg.svg?label=mehrdadrad/mylg)](https://github.com/mehrdadrad/mylg)
[![knq/usql](https://img.shields.io/github/stars/knq/usql.svg?label=knq/usql)](https://github.com/knq/usql)
[![youtube/doorman](https://img.shields.io/github/stars/youtube/doorman.svg?label=youtube/doorman)](https://github.com/youtube/doorman)
[![bom-d-van/harp](https://img.shields.io/github/stars/bom-d-van/harp.svg?label=bom-d-van/harp)](https://github.com/bom-d-van/harp)
[![abiosoft/ishell](https://img.shields.io/github/stars/abiosoft/ishell.svg?label=abiosoft/ishell)](https://github.com/abiosoft/ishell)
[![Netflix/hal-9001](https://img.shields.io/github/stars/Netflix/hal-9001.svg?label=Netflix/hal-9001)](https://github.com/Netflix/hal-9001)
[![docker/go-p9p](https://img.shields.io/github/stars/docker/go-p9p.svg?label=docker/go-p9p)](https://github.com/docker/go-p9p)


## Feedback

If you have any questions, please submit a github issue and any pull requests is welcomed :)

* [https://twitter.com/chzyer](https://twitter.com/chzyer)
* [http://weibo.com/2145262190](http://weibo.com/2145262190)


## Backers

Love Readline? Help me keep it alive by donating funds to cover project expenses!<br />
[[Become a backer](https://opencollective.com/readline#backer)]

<a href="https://opencollective.com/readline/backer/0/website" target="_blank"><img src="https://opencollective.com/readline/backer/0/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/1/website" target="_blank"><img src="https://opencollective.com/readline/backer/1/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/2/website" target="_blank"><img src="https://opencollective.com/readline/backer/2/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/3/website" target="_blank"><img src="https://opencollective.com/readline/backer/3/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/4/website" target="_blank"><img src="https://opencollective.com/readline/backer/4/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/5/website" target="_blank"><img src="https://opencollective.com/readline/backer/5/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/6/website" target="_blank"><img src="https://opencollective.com/readline/backer/6/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/7/website" target="_blank"><img src="https://opencollective.com/readline/backer/7/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/8/website" target="_blank"><img src="https://opencollective.com/readline/backer/8/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/9/website" target="_blank"><img src="https://opencollective.com/readline/backer/9/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/10/website" target="_blank"><img src="https://opencollective.com/readline/backer/10/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/11/website" target="_blank"><img src="https://opencollective.com/readline/backer/11/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/12/website" target="_blank"><img src="https://opencollective.com/readline/backer/12/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/13/website" target="_blank"><img src="https://opencollective.com/readline/backer/13/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/14/website" target="_blank"><img src="https://opencollective.com/readline/backer/14/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/15/website" target="_blank"><img src="https://opencollective.com/readline/backer/15/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/16/website" target="_blank"><img src="https://opencollective.com/readline/backer/16/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/17/website" target="_blank"><img src="https://opencollective.com/readline/backer/17/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/18/website" target="_blank"><img src="https://opencollective.com/readline/backer/18/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/19/website" target="_blank"><img src="https://opencollective.com/readline/backer/19/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/20/website" target="_blank"><img src="https://opencollective.com/readline/backer/20/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/21/website" target="_blank"><img src="https://opencollective.com/readline/backer/21/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/22/website" target="_blank"><img src="https://opencollective.com/readline/backer/22/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/23/website" target="_blank"><img src="https://opencollective.com/readline/backer/23/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/24/website" target="_blank"><img src="https://opencollective.com/readline/backer/24/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/25/website" target="_blank"><img src="https://opencollective.com/readline/backer/25/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/26/website" target="_blank"><img src="https://opencollective.com/readline/backer/26/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/27/website" target="_blank"><img src="https://opencollective.com/readline/backer/27/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/28/website" target="_blank"><img src="https://opencollective.com/readline/backer/28/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/29/website" target="_blank"><img src="https://opencollective.com/readline/backer/29/avatar.svg"></a>


## Sponsors

Become a sponsor and get your logo here on our Github page. [[Become a sponsor](https://opencollective.com/readline#sponsor)]

<a href="https://opencollective.com/readline/sponsor/0/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/0/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/1/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/1/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/2/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/2/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/3/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/3/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/4/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/4/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/5/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/5/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/6/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/6/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/7/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/7/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/8/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/8/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/9/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/9/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/10/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/10/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/11/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/11/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/12/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/12/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/13/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/13/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/14/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/14/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/15/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/15/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/16/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/16/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/17/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/17/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/18/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/18/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/19/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/19/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/20/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/20/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/21/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/21/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/22/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/22/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/23/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/23/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/24/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/24/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/25/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/25/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/26/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/26/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/27/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/27/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/28/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/28/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/29/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/29/avatar.svg"></a>

# Introduction

[![GoDoc](https://godoc.org/github.com/elazarl/goproxy?status.svg)](https://godoc.org/github.com/elazarl/goproxy)
[![Join the chat at https://gitter.im/elazarl/goproxy](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/elazarl/goproxy?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Package goproxy provides a customizable HTTP proxy library for Go (golang),

It supports regular HTTP proxy, HTTPS through CONNECT, and "hijacking" HTTPS
connection using "Man in the Middle" style attack.

The intent of the proxy is to be usable with reasonable amount of traffic,
yet customizable and programmable.

The proxy itself is simply a `net/http` handler.

In order to use goproxy, one should set their browser to use goproxy as an HTTP
proxy. Here is how you do that [in Chrome](https://support.google.com/chrome/answer/96815?hl=en)
and [in Firefox](http://www.wikihow.com/Enter-Proxy-Settings-in-Firefox).

For example, the URL you should use as proxy when running `./bin/basic` is
`localhost:8080`, as this is the default binding for the basic proxy.

## Mailing List

New features will be discussed on the [mailing list](https://groups.google.com/forum/#!forum/goproxy-dev)
before their development.

## Latest Stable Release

Get the latest goproxy from `gopkg.in/elazarl/goproxy.v1`.

# Why not Fiddler2?

Fiddler is an excellent software with similar intent. However, Fiddler is not
as customizable as goproxy intends to be. The main difference is, Fiddler is not
intended to be used as a real proxy.

A possible use case that suits goproxy but
not Fiddler, is gathering statistics on page load times for a certain website over a week.
With goproxy you could ask all your users to set their proxy to a dedicated machine running a
goproxy server. Fiddler is a GUI app not designed to be run like a server for multiple users.

# A taste of goproxy

To get a taste of `goproxy`, a basic HTTP/HTTPS transparent proxy

```go
package main

import (
    "github.com/elazarl/goproxy"
    "log"
    "net/http"
)

func main() {
    proxy := goproxy.NewProxyHttpServer()
    proxy.Verbose = true
    log.Fatal(http.ListenAndServe(":8080", proxy))
}
```

This line will add `X-GoProxy: yxorPoG-X` header to all requests sent through the proxy

```go
proxy.OnRequest().DoFunc(
    func(r *http.Request,ctx *goproxy.ProxyCtx)(*http.Request,*http.Response) {
        r.Header.Set("X-GoProxy","yxorPoG-X")
        return r,nil
    })
```

`DoFunc` will process all incoming requests to the proxy. It will add a header to the request
and return it. The proxy will send the modified request.

Note that we returned nil value as the response. Had we returned a response, goproxy would
have discarded the request and sent the new response to the client.

In order to refuse connections to reddit at work time

```go
proxy.OnRequest(goproxy.DstHostIs("www.reddit.com")).DoFunc(
    func(r *http.Request,ctx *goproxy.ProxyCtx)(*http.Request,*http.Response) {
        if h,_,_ := time.Now().Clock(); h >= 8 && h <= 17 {
            return r,goproxy.NewResponse(r,
                    goproxy.ContentTypeText,http.StatusForbidden,
                    "Don't waste your time!")
        }
        return r,nil
})
```

`DstHostIs` returns a `ReqCondition`, that is a function receiving a `Request` and returning a boolean.
We will only process requests that match the condition. `DstHostIs("www.reddit.com")` will return
a `ReqCondition` accepting only requests directed to "www.reddit.com".

`DoFunc` will receive a function that will preprocess the request. We can change the request, or
return a response. If the time is between 8:00am and 17:00pm, we will reject the request, and
return a precanned text response saying "do not waste your time".

See additional examples in the examples directory.


# Type of handlers for manipulating connect/req/resp behavior

There are 3 kinds of useful handlers to manipulate the behavior, as follows:

```go
// handler called after receiving HTTP CONNECT from the client, and before proxy establish connection 
// with destination host
httpsHandlers   []HttpsHandler
    
// handler called before proxy send HTTP request to destination host
reqHandlers     []ReqHandler 
    
// handler called after proxy receives HTTP Response from destination host, and before proxy forward 
// the Response to the client.
respHandlers    []RespHandler 
```

Depending on what you want to manipulate, the ways to add handlers to each handler list are:

```go
// Add handlers to httpsHandlers 
proxy.OnRequest(Some ReqConditions).HandleConnect(YourHandlerFunc())

// Add handlers to reqHandlers
proxy.OnRequest(Some ReqConditions).Do(YourReqHandlerFunc())

// Add handlers to respHandlers
proxy.OnResponse(Some RespConditions).Do(YourRespHandlerFunc())
```

For example:

```go
// This rejects the HTTPS request to *.reddit.com during HTTP CONNECT phase
proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("reddit.*:443$"))).HandleConnect(goproxy.RejectConnect)

// This will NOT reject the HTTPS request with URL ending with gif, due to the fact that proxy 
// only got the URL.Hostname and URL.Port during the HTTP CONNECT phase if the scheme is HTTPS, which is
// quiet common these days.
proxy.OnRequest(goproxy.UrlMatches(regexp.MustCompile(`.*gif$`))).HandleConnect(goproxy.RejectConnect)

// The correct way to manipulate the HTTP request using URL.Path as condition is:
proxy.OnRequest(goproxy.UrlMatches(regexp.MustCompile(`.*gif$`))).Do(YourReqHandlerFunc())
```

# What's New

1. Ability to `Hijack` CONNECT requests. See
[the eavesdropper example](https://github.com/elazarl/goproxy/blob/master/examples/goproxy-eavesdropper/main.go#L27)
2. Transparent proxy support for http/https including MITM certificate generation for TLS.  See the [transparent example.](https://github.com/elazarl/goproxy/tree/master/examples/goproxy-transparent)

# License

I put the software temporarily under the Go-compatible BSD license.
If this prevents someone from using the software, do let me know and I'll consider changing it.

At any rate, user feedback is very important for me, so I'll be delighted to know if you're using this package.

# Beta Software

I've received positive feedback from a few people who use goproxy in production settings.
I believe it is good enough for usage.

I'll try to keep reasonable backwards compatibility. In case of a major API change,
I'll change the import path.
