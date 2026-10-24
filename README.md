# Alertmanager

An Antimatter app that posts Prometheus Alertmanager alerts in channels, lets people silence them from
the post, and gives agents tools to list alerts and manage silences.

## Features

- **Alerts in channels.** Each Alertmanager instance sends its webhooks to the app. Its routes map
  Alertmanager receivers to channels; the app's bot, *Alertmanager*, posts each alert group there as a
  card: status and severity colour, alert name, instance, summary and description, start time and a
  link to the alert's source. Alerts for receivers without a route are ignored.
- **One post per alert group.** Repeats of a firing group update its post. When the group resolves,
  the post turns green and gets a *Resolved* reply. A group that fires again later gets a new post.
- **Watchdog alerts stay quiet.** Alerts labelled `severity="none"` aren't posted, unless the setting
  says otherwise.
- **Silences from the post.** *Silence 1h*, *Silence 4h* and *Silence until…* (a dialog with a date and
  time, and a comment) create an Alertmanager silence that matches the group: its group labels, with its
  alert name and instance. The post then says who silenced it and until when, and offers *Expire
  silence*. Each silence and expiry is also replied in the post's thread.
- **Who may silence** is a setting: channel admins and community admins (the default), anyone who can
  post in the channel, or system admins only. In every case the person must be a member of the channel.
- **Agents' tools** (for servers with agents):

  | Tool | Kind | What it does |
  |---|---|---|
  | `list_alerts` `{instance?, receiver?, filter?, active?, silenced?, inhibited?}` | read | Alerts of the receivers routed to channels the person can read. |
  | `list_silences` `{instance?, filter?}` | read | Active and pending silences of the instances routed to a channel the person can read. |
  | `create_silence` `{instance?, matchers, duration, comment}` | external write | A silence of up to 30 days. Needs the silence right in every channel the instance is routed to. |
  | `expire_silence` `{instance?, id}` | external write | Ends a silence. A silence set from an alert post needs the right in that post's channel; any other, in every channel the instance is routed to. |

  The server asks the person to confirm the two write tools; the app checks their right all the same.
  Results are compact JSON with a `title` and a `summary`.

## Installation

Upload the bundle in **System Console > Plugins > Plugin Management** and enable it. It needs a server
with agents' tools (`RegisterAITools`, 11.11 or later).

## Settings

- **Alertmanager instances**: a JSON list.

  ```json
  [
    {
      "name": "prod",
      "url": "http://alertmanager:9093",
      "routes": [
        {"receiver": "antimatter", "team": "ops", "channel": "alerts"},
        {"receiver": "db", "channel_id": "<channel id>"}
      ]
    }
  ]
  ```

  `team` and `channel` are the names in the community's and channel's addresses. The URL may be on a
  private network or the loopback address; link-local and cloud metadata addresses are refused.
- **Instance secrets**: a JSON object, a secret setting (never shown again or sent to browsers).

  ```json
  {"prod": {"webhook_secret": "<at least 24 characters>", "bearer_token": "<optional>"}}
  ```

  or `"username"` and `"password"` for basic auth. Webhook secrets may hold letters, digits and
  `. _ ~ -`; `openssl rand -hex 24` makes a good one.
- **Who may silence alerts** and **Post alerts with severity "none"**, as above.

Then point Alertmanager's receiver at the app:

```yaml
receivers:
  - name: antimatter
    webhook_configs:
      - url: https://chat.example.com/plugins/com.antimatterchat.alertmanager/webhook/prod/<webhook secret>
        send_resolved: true
```

## How it works

- The webhook takes Alertmanager's webhook JSON, version 4, at
  `POST /plugins/com.antimatterchat.alertmanager/webhook/{instance}/{secret}`. An unknown instance and a
  wrong secret get the same `404`; secrets are compared in constant time. Each instance may send 60
  webhooks at once and 2 a second after that (`429` beyond); bodies are capped at 1 MiB (`413`).
  The app never logs the path.
- The post of a group in a channel is a `grp_<hash>` key in the app's KV store, holding the group's
  labels, its last alerts and the silence set from the post. Posts are message attachments, which every
  client shows; the buttons are attachment actions served by the app at `/action`, and *Silence until…*
  is an interactive dialog served at `/dialog`. Both check the person the server routes the click for,
  the post and its channel, and the silence right, on every click.
- Requests to Alertmanager use its v2 API (`GET /api/v2/alerts`, `GET /api/v2/silences`,
  `POST /api/v2/silences`, `DELETE /api/v2/silence/{id}`), with a dialer that refuses link-local,
  metadata, multicast and unspecified addresses (checked after name resolution), no proxy from the
  environment, and no redirects.

## Development

```sh
make dist        # builds the bundle in dist/
make test        # runs the server tests
```
