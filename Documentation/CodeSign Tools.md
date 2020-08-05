Starting with iOS 12, Apple introduced CoreTrust, which ensures that the binary you attempt to run (being it a full blown .app file or just a Mach-O binary) has a valid CodeSign blob with a valid ``Apple Developer Relations certificate``. 

Starting with CoreTrust on iOS 12, in order for a binary to not be killed by AMFI (Apple Mobile File Integrity) on the spot with the dreaded "Killed: 9" error, it must:

* Have a valid CodeSign blob.
* Have a valid certificate embedded in it.
* Have a SHA-256 hash embedded (other variants still produce the crash, some older tools sign with SHA-128, not good).
* Have the right entitlements embedded into it.
* Not violate entitlements policies (AMFI won't just let you slap any entitlement on yourself if you aren't platform!).

## Tools for fake-signing
For properly code-signing the base binaries for the jailbreak I personally use jtool2 created by Jonathan Levin. It does sign properly (SHA-256) (fake signing), but if you use it to sign your binaries, you must add all of them to AMFI's dynamic TrustCache which may or may not be a good idea depending on the scale of your jailbreak. 

* Jtool2 can be found here: http://www.newosxbook.com/tools/jtool.html

### Example signing with jtool2, with an entitlements XML file:
`jtool2 --sign --ent Entitlements.xml /Users/geosn0w/Desktop/dropbear`

### Checking the signature of a Mach-O binary with jtool2:
`jtool2 --sig --ent /Users/geosn0w/Desktop/dropbear`

## Tools for real-signing (as in, signing with certificate and all that)
This has the advantage that you don't necessarily need to add every single binary to AMFI's TrustCache, but you do need a real Apple certificate. A p12 or even your own Apple Developer ID. 

For this I usually use codesign (built-in on macOS). It does allow you to add entitlements from an XML file which is neat, and it allows you to select a signing identity from the Keychain. 

For more info on the usage, run `man codesign` in Terminal.

## For questions:

* GeoSn0w (@FCE365): https://twitter.com/FCE365
* YouTube: iDevice Central: https://www.youtube.com/fce365official
