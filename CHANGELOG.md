# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [2.1.3] - TBD

### Changed

- Timeout state improved (intermediary state to confirm timeout)

## [2.1.2] - Skipped official release

### Added

- Disconnected / no response timeout state, so if no responses are received (maybe disconnected/offline) the message queue shouldn’t drown in unhandled requests.

- Auto Sourcer + Stamp Converter! -> Auto Sourcer, already has the main three available and known sources preloaded by default (and a source with my providers during testing, demonstrating the ease of adding or making/using your own provider sources resources), and you can easily add further sources if/when they’re available or change web locations. HTTPS (port 443) and HTTP (port 80) sources locations supported.

### Changed

Much more user-friendly! Now you don’t need to manually look at provider sources and pick and choose which ones to then copy and paste one by one into the application… You can instead load (from saved once retrieved recently) or download/update source lists from their urls that are in the standard simple format, select them to decode and see what server info is actually contained, change server parameter to re-encode the server info back to stamp form and finally click “ADD IT!” button to add to your dns providers / dns servers list!

The stamp converter supports protocols v1,v2,v3 (v0 is just plain dns, it can read them but won’t use them if DNSCrypt is enabled)

- Reduced DoH + DoTLS request handling objects into one object that handles both (they were so similar, I realized I could just make them one type)

- Fixed some small things, noticed incorrect while adding this (like v2 or v3 stamp reading when no hashes provided, if the first hash’s length is zero just skip trying to read hashes since none were provided)

## [2.1.1] - 2018-05-21

### Changed

- DNS over TLS fixed and working properly now! -> The provided hostname doesn’t necessarily resolve to the right ip to use for DoTLS. Since QSSlSocket inherits from QTcpSocket, I can therefore use connectToHost rather than connectToHostEncrypted (which doesn’t take an ip, only a hostname) and use startEncryption function manually. Using the provided IP address in the stamp if there is one now correctly connects to the DoTLS provider! Also added the 2 byte length prefix that I forgot initially. So now both DNS over HTTPS and DNS over TLS work! :)

- Like noted in the dnscrypt stamp specification, if there is no IP address provided or its just a port, it’ll use the hostname instead (a stamp like this should indicate the hostname will resolve to the correct ip to use) and use the port from either place it’s located. So even in that edge case it’ll still work properly!

### Notes

Alright what else is there to do now? Perhaps have a list of DNSCrypt provider sources to auto download from (might as well since we have a TLS stack now) and let you easily select and add them not requiring manual copying and pasting anymore. Also an inbuilt stamp converter to create stamps from specified server info, or vice versa. (Like `dnscrypt.info’s` but also doing protocol v3 [I had to manually change the start to `sdns://Aw` (protocol version 3) in my testing of v3 servers])

## [2.1.0] - Untagged

### Added

- DNS over HTTPS / DoH support!

- DNS over TLS / DoTLS support added!

    - Note: If using DoH and/or DoTLS providers you should set a dedicated v1 DNSCrypt provider to use to resolve the hosts of DoH and DoTLS providers themselves! :)

### Changed

- Props info now displayed as well for last used provider

## [2.0.7] - Untagged

### Changed

- Better handling of multiple DNSCrypt providers

- Last DNSC provider used is displayed on the main window

- PlainDNS can specify a port now too, ex. 208.67.222.222:53 (when DNSCrypt is disabled)

- Fixed too small of a font used on macOS ->Now I’m truly ready to add protocolVersion 2 & 3 support

## [2.0.0] - Untagged

### Added

- DNSCrypt now supported! Very happy I made it this far! You locally send it standard plaintext requests as usual and it transparently dnscrypts them for you using the dnscrypt providers you’ve specified. Now your queries aren’t going over the wire as plaintext anymore! Enabled by default! No fallback (must disable DNSCrypt to use plaintext dns servers again)

- Can enable new key pair per request otherwise a new key pair is made on every newly validated certificate for that provider.

- Added a cache viewer

- Mac + Windows + Android v2.0 builds are now available!

### Changed

- IPv6 has been supported without me realizing it since I’ve supported every record type (not just A)! So now I’ve made it also listen on ipv6 addresses as well as ipv4 addresses so now you can not only get ipv4/ipv6 addresses connecting to the server over ipv4 but also connecting to it over ipv6 now as well. (You can set it as an ipv6 dns server)

### Notes

Just add DNSCrypt stamps in settings to the list of dns servers and make sure enable DNSCrypt checkbox is checked to use them! ex. `sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ` Corresponds to: 

```sh
Protocol version 0x0001 read -> DNSCrypt!
Provider using IPv4 address: "208.67.220.220"
Provider PubKey acquired...
len: 32
Provider name: "2.dnscrypt-cert.opendns.com"
len: 27
```

Currently protocol version 2 (DoH / DNS over HTTPS) isn’t implemented yet, so if adding them they won’t be used at the moment. I do like how all the necessary information is all contained in the base64 encoded string, so I adopted the stamps as well. No auto sourcing them for now though, manually add them [from here](https://github.com/jedisct1/dnscrypt-proxy/wiki/DNS-server-sources)

## [1.1.9] - Untagged

### Changed

- Another slight reduction (adding and using getListEntry similar to when I added getCachedEntry)

- Fixed multiple cache entries for the same domain if it was requested with changed cases -> (ex. `gItHuB.com` instead of `github.com`) -> Despite checking each domain with a case insensitive match with wildcard support I still inserted into the cache and checked against it an a case sensitive way. ->To solve it I changed this one line: `dns.domainString = fullname;` to `dns.domainString = fullname.toLower();` which is upon first interpreting the domain. ->Now if an altered case domain name is given (ex. `ExAMpLE.CoM` it’s always seen as `example.com`, anywhere in the application after it’s first interpreted)

- Also fixed customized dns and http server ports not actually being used by preloading the dns and http server ports from the config file right away, and reading the other info from it later. -> I noticed this when setting the dns and http server ports above 1024 saving it and running it not as root and it still attempted to bind to port 53 and 80 ignoring the config (because I was reading it too late after the servers were already initialized and started) -> Now you can run it as non root, if you have and prefer some other way to redirect ports 53 and 80 to it (like iptables which I use on android in here [that itself still requires root though]) or if you can specify a port for your dns server on whatever device you’re using and obviously you can for http. (But it won’t really work as an auto captive portal in that case)

## [1.1.8] - Untagged

## Added

- Added customizable DNS TTL instead of hard coded, or auto setting matching your cached entry minutes valid value but in seconds.

## Changed

- Cleaner code exists (freeing up objects created)

## [1.1.7] - Untagged

### Changed

- Code refactoring for better performance

## [1.1.6] - Untagged

- Code refactor and minor adjustments

### Changed

- Recursion flag now set, which eliminates the 'recursion requested but not available' warning from dig
- Responding to NXDOMAIN immediately with injected ip / custom ip instead of delaying at all... (I'm interpreting NXDOMAIN response code now, to respond immediately to it)
- Using the DNS_HEADER structure now when producing answer responses instead of manual offsets with constants

### Notes

1.1.5 is a beautiful version, I feel like everything is working correctly now.

## [1.1.4] - Untagged

### Added

- Added new blacklist default "*cdn.nintendo.net"

### Changed

- Cache was only being triggered to be used after each second request for a certain domain, instead of after the first request. 

Example:
```
Request: github.com
Get: ips for requested site, add to  cache
Return: response
    Request: github.com
    Get: ips for requested site, add to cache
    Return: response
Request: github.com
Return: cached ips built response
```

This is repeated until the ips expire upon which it will do the process again. The indented section no longer occurs and is skipped entirely as it should be.

## Notes

Nothing major this time, but still the cache should be working properly and now it is again!

## [1.1.3] - Untagged

### Changed

- Whitelist mode was broken in 1.1.2, it is now fixed and working again.

- Instantly responding to requests was broken in 1.1.2, now it's working again too.

### Notes

- That should be the last time anything major is broken at least until 1.2+ hopefully! :)

- 1.1.3 is a needed update if you have 1.1.2, so make sure to upgrade to it for improved experience.

## [1.1.2] - Untagged

### Added 

- Build in single file replayer http server (it just replays the same html you specify for any request) 

  - `index.html` file can be edited from the settings
  - port of the http server can be customized, 0 is off, by default it's 80, which goes to port 8080 on android (and iptables 80 -> 8080)
  - port of the dns server can now be customized also, unlike it however, 0 is port 53 still

- Auto injects the servers first found listening ip by default (ip of dns and now http server) (OOB captive portal capturing)

- Upon loading of new version, auto blacklisting of known captive portal urls happens and it's an option in the settings

### Changed 

- Improved caching! Now caches and returns for all dns query types instead of just A records. [Android Specific]

- Event processing now moved to a background thread, allowing it to now entirely run both the dns and http server in the background on android!
  - You can now minimize it, and it will stay working in the background (no longer depending on gui being visible). As long as the app stays running it'll stay working!
  - Even though I'm creating some threads it's still ansynchronous. Those threads are to process the ansynchronous events, seperate from the main thread.

- Gui looks better on android and is more readable

- Now only inserts the iptables forwarding once, so it doesn't just keep inserting the same thing every new running instance into iptables

- Runs those iptables inserting with su privileges in it's own thread as well so it also doesn't block the main thread either. [Bugfixes since 1.0]

- Fixed crash on no ip addresses at all received from real dns server for A record (What it does now instead of crashing is a delayed not able to load, and then it redirects to the injected ip / server ip / custom ip)

- Don't allow blank entries in either lists or dns server box

- Improved handling of other dns types and of A records themselves too