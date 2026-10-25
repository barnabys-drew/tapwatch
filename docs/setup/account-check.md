# Account check: what was that upload to Google?

`upload_spike` sees that a device sent, say, 1.5 GB to `content-storage-upload.googleapis.com`. That's
Google's upload service, used by Drive, Gmail attachments and YouTube. The network can't say what the upload
was, but the account can. The account check asks your own Google accounts, read-only, what was uploaded in the
hours of the case:

| Source | Scope (read-only) | What it gives |
|---|---|---|
| Drive Activity API v2 | `drive.activity.readonly` | files created or uploaded: when, how (upload, copy, new), file type |
| YouTube Data API v3 | `youtube.readonly` | videos added to the channel's uploads |
| Gmail API | `gmail.metadata` (restricted) | sent and draft messages: when, and size. Attachments over 25 MB become Drive links, which Drive Activity shows |

It's opt-in and runs on demand: `tapwatch account-check <case> [--save]`, or from the `enrich-case` skill. The
alerter never calls Google.

```
$ tapwatch account-check 986 --save
Account check 21:29-00:29 UTC: personal: Drive shows 2 files created or uploaded at 23:44-23:58 UTC (2 video/mp4);
YouTube shows nothing; Gmail shows nothing | work: Drive shows nothing; Gmail shows nothing
```

With `--save`, the result goes onto the case as an `account_check` fact plus a note, recorded in the audit
trail. Only counts, file types, times and sizes are saved, never file names, subjects or recipients. `--names`
prints Drive and YouTube titles to your terminal only.

## What it can't see

- **Google Photos backups.** Since 2025 the Photos Library API only sees media the calling app created, so a
  phone's photo backup can't be checked this way.
- **My Activity** has no API, and it doesn't list Drive uploads anyway.
- **iCloud** has no usable API. Apple uploads stay network-only.
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
5. List the labels in `config.yaml`:
   ```yaml
   account_check:
     google: [personal, work]
   ```

The refresh tokens are kept in `~/.local/state/tapwatch/accounts/` (one file per label, mode 600). `tapwatch
accounts list` shows them, and `tapwatch accounts remove <label>` deletes one and withdraws it at Google. You can
also remove tapwatch at [myaccount.google.com/permissions](https://myaccount.google.com/permissions).
