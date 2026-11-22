# Troubleshooting

[← back to the README](../README.md)

## The report says "OSV could not be reached"

**What it means.** stack-guard checks your packages by asking [OSV.dev](https://osv.dev), the free public database of known security problems. From 1.10.0, when it can't reach OSV it asks a second layer instead: the npm registry for your npm packages and PyPI for your Python packages in the daily check, and GitHub's advisory database for malware in the install-time `lock-check`. Look for this line under **Not checked**:

> OSV (known security problems) could not be reached: URLError. No package was checked.

**If the report also says** "OSV could not be reached; packages were checked with the npm registry and PyPI instead", the second layer answered and the report shows real findings. Two differences: Python packages show severity UNKNOWN (PyPI gives none), and npm findings list no fixed version. Go, Rust, Ruby and PHP packages are not covered by the second layer, and the report counts them under **Not checked**. At install time, a malware record in GitHub's database is flagged MALICIOUS (exit 4). GitHub allows 60 lookups an hour without a token; set `GITHUB_TOKEN` or `GH_TOKEN` to raise that. If GitHub does not answer, `lock-check` says "malware check not done" (exit 2).

**If it does not,** every source failed and that day's report says nothing about your packages. "None" under 🔴 Fix first does not mean you are safe. It means nothing was looked up. (Before 1.9.1 the report printed "None" there anyway. From 1.9.1 it says "not checked".)

**Find out where it breaks.** Run these three commands in a terminal:

```sh
curl -sI https://osv.dev | head -1                        # the website
curl -sI https://www.google.com | head -1                 # the internet in general
curl -v -m 15 https://api.osv.dev/ 2>&1 | grep '^\*'      # the address stack-guard uses
```

- **All three answer:** it was a short outage. The next daily run will check again.
- **Nothing answers:** you were offline when the check ran.
- **The first two answer, but the `api.osv.dev` command times out:** traffic between you and OSV's servers is being dropped. The verbose output shows where. If it stops at `Trying …`, the connection never opened. If it shows `Connected` and then stops, the connection opened but the secure (HTTPS) handshake never finished. The cause is most likely your internet provider, a firewall, a work network or a VPN. stack-guard is not involved, since plain `curl` fails the same way. Try the same command on another network, such as a phone hotspot or a VPN. If it works there, the problem is your usual network's route to OSV.

**Check your packages by hand when every source is unreachable.** These use other advisory sources (`npm audit` asks the npm registry, `pip-audit` asks PyPI by default):

```sh
npm audit --omit=dev      # in each Node project
pip-audit                 # in each Python project, if you have it installed
```

**Is OSV down, or is it my network?** The three commands above tell you. OSV's API failed from several networks on 7 and 15 to 17 Nov 2026, so it is not only a home-connection problem. From 1.10.0 a slow or unreachable OSV no longer stops the check, because the npm registry and PyPI answer in its place. Ask again with the commands when you want to know whether OSV itself is back.

**Seen in the wild.** On 15 Nov 2026 a home connection in Indonesia could open `osv.dev` and other Google sites, but not `api.osv.dev`. Some of its addresses never accepted a connection, and others accepted one but never finished the handshake. It was still failing hours later, so it was a lasting route problem, not a short outage.
