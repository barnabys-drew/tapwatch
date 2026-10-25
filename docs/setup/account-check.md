# Account check: what was that upload to Google?

`upload_spike` sees that a device sent, say, 1.5 GB to `content-storage-upload.googleapis.com`. That's one of
Google's upload endpoints. It has been seen carrying Drive, Gmail-attachment and YouTube uploads, but Google doesn't
document which service uses it, so the check asks all three. The network can't say what the upload
was, but the account can. The account check asks your own Google accounts, read-only, what was uploaded in the
hours of the case:

| Source | Scope (read-only) | What it gives |
|---|---|---|
| Drive Activity API v2 | `drive.activity.readonly` | files the account itself created, uploaded or replaced with a new version in My Drive: when, how, file type |
| YouTube Data API v3 | `youtube.readonly` | videos added to the channel's uploads |
| Gmail API | `gmail.metadata` (restricted) | sent and draft messages: when, and size. Attachments over 25 MB become Drive links, which Drive Activity shows |

It's opt-in and runs on demand: `tapwatch account-check <case> [--save]`, or from the `enrich-case` skill. The
alerter never calls Google.

```
$ tapwatch account-check 986 --save
Account check 21:29-00:29 UTC: personal: Drive shows 2 files created or uploaded at 23:44-23:58 UTC (2 video/mp4);
YouTube shows nothing; Gmail shows nothing | work: Drive shows nothing; Gmail shows nothing
```

There are three outcomes, plus a variant of the second:
- **Explained:** something in the window could account for the upload. Drive and YouTube give no sizes, so any
  file or video there counts. Gmail gives sizes, so a few small emails beside a 1.5 GB upload don't: the summary
  then says there was "nothing big enough to explain" it.
- **Unexplained:** every account was fully checked and shows nothing.
- **Possibly managed account:** unexplained, but during the upload the device looked up or connected to a name
  only a managed (work or school) Google account produces, such as `ios-mdm.google.com`, Google's iOS device
  management endpoint. A work or school account on the device may explain the upload, and the check can't see
  it. The device's DNS and TLS records come from the same Zeek logs the case pages read (`ui.zeek_dirs`, or
  `--zeek-dir`); without them the outcome stays unexplained. The marker list is `MANAGED_MARKERS` in
  `src/tapwatch/accounts.py`.
- **Incomplete:** a check failed, stopped before covering the whole window, or no account is set up. Incomplete
  says nothing either way, so treat it as no answer.

With `--save`, the result goes onto the case as an `account_check` fact plus a note, recorded in the audit
trail. Only counts, file types, times and sizes are saved, never file names, subjects or recipients. `--names`
prints Drive and YouTube titles to your terminal only.

## What it can't see

- **Google Photos backups.** Since 2025 the Photos Library API only sees media the calling app created, so a
  phone's photo backup can't be checked this way.
- **My Activity** has no API, and it doesn't list Drive uploads anyway.
- **iCloud** has no usable API. Apple uploads stay network-only.
- **Shared drives.** Drive Activity covers My Drive by default, and listing shared drives would need another
  scope. Uploads into a shared drive don't show up.
- **Work or school accounts.** A managed Google Workspace account signed in on the device (in Gmail, say) can
  upload just like a personal one, and the check can't sign in to it. The most it can do is notice the device
  talking to Google's device management, as above.
- **File sizes in Drive.** Drive Activity doesn't include them, and reading them would need another restricted
  scope. Gmail sizes are included.
- **Message contents.** The Gmail metadata scope reads dates and sizes; tapwatch doesn't ask for anything else.

## Set up (once, about 10 minutes)

1. In the [Google Cloud console](https://console.cloud.google.com/), in any project of yours, enable the
   **Drive Activity API**, the **YouTube Data API v3** and the **Gmail API**.
2. Under **APIs & Services → OAuth consent screen**, set the app up as **External**, then set the publishing
   status to **In production**.
   - **Why production:** in *Testing*, Google expires refresh tokens after 7 days, so the check would stop
     working every week.
   - **Unverified is fine:** an app that's in production but unverified shows an "unverified app" warning at
     sign-in, which is fine for your own accounts. Google requires verification only to offer restricted
     scopes, such as Gmail metadata, to other people.
3. Under **Credentials**, create an **OAuth client ID** of type **Desktop app**. Put it in the tapwatch
   folder's `.env` on the sensor:
   ```
   TAPWATCH_GOOGLE_CLIENT_ID=...
   TAPWATCH_GOOGLE_CLIENT_SECRET=...
   ```
4. On the sensor, add each account under a label (a name, never the address):
   ```
   tapwatch accounts add personal
   ```
   - **Sign-in:** it prints a Google sign-in link. Open it on any computer, sign in to that account, approve,
     and click past the unverified-app warning.
   - **Finish:** the browser then fails to load a `127.0.0.1` page. Copy that page's whole address back into
     the prompt.
   - **Fewer scopes:** `--services drive,youtube` grants less.
   - **One label per account:** Google always shows its account chooser. If a second label signs in to an account
     that's already saved, nothing is saved and you're told so. A private window makes signing in to the other
     account easy.
5. List the labels in `config.yaml`:
   ```yaml
   account_check:
     google: [personal, work]
   ```

The refresh tokens are kept in `~/.local/state/tapwatch/accounts/` (one file per label, mode 600). `tapwatch
accounts list` shows them, and `tapwatch accounts remove <label>` deletes one and withdraws it at Google. You can
also remove tapwatch at [myaccount.google.com/permissions](https://myaccount.google.com/permissions).

Moving tapwatch to another computer (`deploy/export-state.sh`) carries `.env` but not the token folder. Add the
accounts again there, or copy the folder over yourself and keep it mode 700.
