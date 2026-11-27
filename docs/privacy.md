# Where your files go

Verdyx is private by default. Your files stay with Verdyx, and your reports
are yours, or your team's, until you choose otherwise.

## Your files

An uploaded file is stored by Verdyx (in Cloudflare R2) and read by Verdyx's
own engines: the static, heuristic, YARA and signature engines, the
Office/PDF/Android analyzers, ClamAV and the Windows-program model. These all
run on Verdyx's servers.

**Other services get the file's hash, not the file.** A hash is a fingerprint:
it can't be turned back into the file. Scans look the hash up on:

| Service | What it's sent |
|---|---|
| VirusTotal | the hash, to read its last analysis (and, for Behavioral analysis, its sandbox report) |
| MalwareBazaar (abuse.ch) | the hash, to check its list of known malware |
| Hybrid Analysis | the hash, when Verdyx has a key for it |

**The one exception is Behavioral analysis.** If VirusTotal has no sandbox
report for the file, Behavioral analysis can upload the file so VirusTotal's
sandboxes run it. VirusTotal keeps uploaded files and its customers can
download them, so this is **off by default**:

- For scans you save to your own account, you decide: profile → **Account** →
  **Privacy** → *Let Behavioral analysis upload my files to VirusTotal*.
- For scans saved to a team, the team decides. Owners and admins set it in the
  same place.
- Scans made while signed out never upload their file.
- The choice is recorded on each scan when it's made. Changing it later
  doesn't affect earlier scans.

When the upload isn't allowed, the report says so: *"The file wasn't
uploaded: sharing files with VirusTotal is off in your privacy settings."*
Every report also says whether its file stays with Verdyx.

## Web addresses

A URL scan visits the address from Verdyx's servers, and looks it up on
VirusTotal, Google Safe Browsing, URLhaus and ThreatFox. These services see the
address, including anything in it such as a query string. Don't scan an
address that carries a password or a private token.

## Who can open a report

| Scan | Who can open it |
|---|---|
| Saved to your account | You |
| Saved to a team | The team's members, and the team's API keys |
| Posted with a bounty | Any signed-in analyst, so they can work on it |
| Shared by link | Anyone with the link, signed in or not |
| Made while signed out | Anyone with the link, since there's no account to tie it to |

Verdyx administrators can open any scan, for support and abuse handling.

**Sharing by link** is off for every scan until its owner turns it on, with
the *Share by link* switch at the top of the report. Whoever may delete the
scan may change it: the person who made it, or a team owner or admin. It can
be turned off again at any time. Each change is written to the activity log.

A scan shared by link doesn't show up anywhere else: not in anyone's lists,
similarity search, live hunts or retrohunts. Those only cover scans you could
already open without the link.

## How long it's kept

Uploaded files are deleted after a set time, and you can choose how long
scans are kept, or delete one at any time. See profile → **Account** → **Keep
my scans**.

## API

| Request | What it does |
|---|---|
| `GET /api/v1/users/me/privacy` | Your setting, and your teams' |
| `PUT /api/v1/users/me/privacy {"shareFilesWithVirusTotal": true}` | Change yours (sessions only) |
| `PUT /api/v1/orgs/{id}/privacy {"shareFilesWithVirusTotal": true}` | Change a team's (owners and admins) |
| `PUT /api/v1/submissions/{id}/sharing {"sharedByLink": true}` | Share a report by link, or stop |

Each scan's JSON has `sharedByLink` and `mayUploadFile`.
