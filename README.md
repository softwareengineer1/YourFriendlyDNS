# YourFriendlyDNS
A really awesome multi-platform (lin,win,mac,android) local caching and proxying dns server!

{Version 1.1.4}
[Bugfix release]
1. Cache was only being triggered to be used after each second request for a certain domain, instead of after the first request.
(Ex. request github.com -> get ips for it cache them -> return response, request github.com -> get ips, cache them -> return response, request github -> return cached ips built response. (until it expires then it will do this again)
Now it will properly just do:
request github.com -> get ips for it cache them -> return response, request github -> return cached ips built response. (until it expires then it will do this again))
2. Added new blacklist default "*cdn.nintendo.net"
So yes nothing major this time, but still the cache should be working properly and now it is again!

{Version 1.1.3}
[Bugfix release]
1. Whitelist mode was broken in 1.1.2, it is now fixed and working again.
2. Instantly responding to requests was broken in 1.1.2, now it's working again too.
 ->That should be the last time anything major is broken at least until 1.2+ hopefully! :)
  ->1.1.3 is a needed update if you have 1.1.2, so make sure to upgrade to it for improved experience.

{Version 1.1.2}
[Features since 1.0]
 1. Inbuilt single file replayer http server (it just replays the same html you specify for any request)
   ->"index.html" file can be edited from the settings
   ->port of the http server can be customized, 0 is off, by default it's 80, which goes to port 8080 on android (and iptables 80 -> 8080)
   ->(port of the dns server can now be customized also, unlike it however, 0 is port 53 still :))
 2. Auto injects the servers first found listening ip by default (ip of dns and now http server) (OOB captive portal capturing)
 3. Upon loading of new version, auto blacklisting of known captive portal urls happens and it's an option in the settings
 4. Improved caching! Now caches and returns for all dns query types instead of just A records.
 [Android Specific]
 5. Event processing now moved to a background thread, allowing it to now entirely run both the dns and http server in the background on android!
   ->You can now minimize it, and it will stay working in the background (no longer depending on gui being visible). As long as the app stays running it'll stay working!
   ->Even though I'm creating some threads it's still ansynchronous. Those threads are to process the ansynchronous events, seperate from the main thread.
 6. Gui looks better on android and is more readable
 7. Now only inserts the iptables forwarding once, so it doesn't just keep inserting the same thing every new running instance into iptables
 8. Runs those iptables inserting with su privileges in it's own thread as well so it also doesn't block the main thread either.
[Bugfixes since 1.0]
 9. Crash on no ip addresses at all received from real dns server for A record
   (What it does now instead of crashing is a delayed not able to load, and then it redirects to the injected ip / server ip / custom ip)
 10. Don't allow blank entries in either lists or dns server box
 11. Improved handling of other dns types and of A records themselves too 


Okay the directions for using with the switch or other use:

Two options:
[One]
To ensure you have the latest version you may want to compile it yourself for your desired platform (Either Linux, Mac, Windows, or Android) [iOS if you're jailbroken and feeling adventurous and know an iptables alternative, For Android your device must be rooted as well]

1. Download and install the free software license (non commercial) version of Qt version 5.10 or later
2. Download the source of the project which contains the .pro file(project file) that opens in Qt
3. Open it in Qt and configure it to be built for your platform (for android must have android sdk and ndk installed for linux,windows,mac it'll automatically let you load it)
4. Do a Ctrl+B or Command+B to build the project! :D Done! Ready to run ->

[Two]
1. Download the whole project (git clone or download zip) and browse to the folder of your platform (Linux-x64 for linux, Mac-x64 for mac, etc...)
2. Copy the entire folder with all the supporting shared libraries to some location you like :D Done! Ready to run ->

Note: It needs to be run as root, so it can bind and listen on udp port 53, that's the only reason it requires it.

Now how to run it :
[Linux]
1. Browse to the directory containing it, right click and choose open terminal at this location.
2. Type sudo ./YourFriendlyDNS and enter your password for your user account (must have sudoer privileges or change to a user that does or to root user)
3. Configure it how you like and use an IP displayed on the GUI "Listening IPs: " text label as your DNS server from any device locally connected to the same network as you're running he DNS server on!

[Mac]
1. Browse to the directory containing it, open a terminal, and drag LaunchYourFriendlyDNSAsRoot.sh onto the terminal window.
2. Enter your password so it's granted root access
3. Configure it how you like and use an IP displayed on the GUI "Listening IPs: " text label as your DNS server from any device locally connected to the same network as you're running he DNS server on!

[Windows]
1. Browse to the directory containing it, and right click YourFriendlyDNS.exe and choose Run As Administrator
2. Okay the privilege escalation box, if it appears, so it''s granted Administrator/root access
3. Configure it how you like and use an IP displayed on the GUI "Listening IPs: " text label as your DNS server from any device locally connected to the same network as you're running he DNS server on!

[Android] (Make sure your device is actually rooted and you can run su with no issues and actually truly do have root)
1. Copy and install the apk to your device, use the one for your Android architecture, either ARM or x86. (You may need to enable installing packages from unknown sources if you haven't already)
2. Run the app and when the su root access prompt is displayed hit accept (you only have to do this once, unless you remove it's priviliges from your su app later)
3. Configure it how you like and use an IP displayed on the GUI "Listening IPs: " text label as your DNS server from any device locally connected to the same network as you're running he DNS server on!
[Note: For Android currently the application's GUI has to stay open and visible for DNS requests and responses to be handled, I'm going to fix this but right now I recommend setting your device to not ever sleep / turn off screen and keep it plugged it or be sure to plug it in when it's low so that your YourFriendlyDNS will remain working on your Android. For Devs: Is there a way I can keep it asynchronous while also running those asynchronous dns handlings from that separate thread from the gui/main thread? Make if I first create a new thread and then connect the signals from that thread instead of from the main thread it'll stay working even when backgrounded (as long as the app remains running) I'll look into it!]

[Usage]
Make sure to take it off of 'Initial Mode/Safe Mode' by unchecking that checkbox once you've configured your whitelist/blacklist and it's safe to do so (whitelist is safe immediately, blacklist should be safe immediately as long as those nintendo update servers have stayed the same)

1. Select Whitelist or Blacklist mode
2. Add domain names to whitelist or blacklist, * wildcards are supported, for example: "*gbatemp.net" matches www.gbatemp.net, gbatemp.net, or anything.anything.gbatemp.net
-> If in whitelist mode, a matched domain that's in the whitelist will be accessible, everything else will not be.
-> If in blacklist mode, a matched domain that's in the blacklist won't be accessible, everything else will be.
-> Things that aren't accessible/are blocked will be directed to 127.0.0.1/localhost by default, unless you have a server on that machine on the port for the service you're accessing (ex. trying to access filtereddomain.domain on a device with this dns server configured on a web browser will redirect to http://127.0.0.1 relative to that device the dns is configured to be used on (so that device itself)). You can change this is the settings so it goes to for example another computer on your local network instead.
-> If you add a hostname/domain and also fill in the custom mapping IP field, the IP in the settings is ignored and the mapped IP is returned for domains that match instead. That also changes the behavior of that item in the list and treats it as a special case, to just return that IP instead of any other (can be use in either whitelist/blacklist mode).
3. Change the settings to keep the cached IPs (for whitelisted/non blacklisted domains) treated as valid for longer or shorter (note: too long and your ips might get stale). The cache not kept between instances of the application (eg. If you restart it, it start's fresh.) You can also clear it forcefully at anytime by hitting the "Clear Cache Now" button. Also you can change the real dns servers to use, by default it uses open dns servers. You can add as many as you like and it randomly selects which one to use each time a request needs to be made.

4. Now you are running your own local caching and proxying dns server! You no longer have to worry about an online one going down, or not working properly, because you can always make sure your locally running one is working because you control when it runs and how it's configured!

Source:
https://github.com/softwareengineer1/YourFriendlyDNS/tree/master/Source/YourFriendlyDNS

Linux Version:
https://github.com/softwareengineer1/YourFriendlyDNS/tree/master/Linux-x64

Mac Version:
https://github.com/softwareengineer1/YourFriendlyDNS/tree/master/Mac-x64

Windows:
https://github.com/softwareengineer1/YourFriendlyDNS/tree/master/Windows-x64

Android ARM:
https://github.com/softwareengineer1/YourFriendlyDNS/tree/master/Android-armeabi-v7a

Android x86:
https://github.com/softwareengineer1/YourFriendlyDNS/tree/master/Android-x86

