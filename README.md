# peer-observer archive viewer

A standalone, static web page for looking inside
[peer-observer](https://github.com/peer-observer/peer-observer) archive files.
Drop a `.bin.zst` (or `.bin`) archive onto it and it decodes the whole thing and
shows what is in there: totals and a per-event-type breakdown, a timeline, a
per-peer view of the eBPF events, and a filterable event table with a full
decode of any event you click.

Everything happens in your browser. Decoding runs in WebAssembly, client-side —
nothing is uploaded, and the page makes no network requests of any kind. There is
no server, no nodejs and no JavaScript framework.

## Using it

Drag one or more archive files onto the page, or press **Open archive…**.

- **Rotated files dropped together** are read as one continuous archive, ordered
  by the timestamp in their filenames.
- **Archives still being written are fine.** They end mid-stream; everything
  before the cut is read and the truncation is reported.
- **Big archives** are handled by always aggregating every event, while retaining
  the event bytes only up to a memory budget (512 MB by default, selectable in
  the bar). Past that the event table and inspector cover the first *N* events and
  say so; the totals, charts and peer statistics still cover everything.
- **Raw transaction and block data is not retained.** It is most of a full-data
  archive and no view reads it, so the retained copy is stripped of exactly what
  peer-observer's own `--low-data` mode strips: transactions keep their txid and
  wtxid, blocks keep their header, and the wire size stays on the message
  metadata. Aggregation still runs over the complete event.

Two things the archive format cannot tell you, which the page says so you don't
have to guess:

- Which event types an archive contains depends on the flags the producing
  archiver ran with (`--messages`, `--connections`, …), and those flags are not
  recorded in the file. An event type that is absent may simply have been
  filtered out at capture time.
- Peer ids are assigned by Bitcoin Core and are only unique within one node run,
  so an archive spanning a restart can reuse them.


## Views

**Overview** — totals, the event breakdown, all events over time, and one group
broken down by type (the connection rate by inbound/outbound/closed/evicted).

**Peers** — every peer with its message mix and connection lifecycle, or the same
peers grouped by **network**. Grouping uses Bitcoin Core's own asmap trie, the
IP-to-ASN mapping Core uses to bucket peers for eviction, so the viewer groups
peers the way Core reasons about them. This matters: in one sample archive the
peer list showed 158,450 addresses, and the network view showed that 99.1% of
them were a single autonomous system with a 99.9% eviction rate. Grouping by IP
prefix would have split that one actor across four buckets.

**Events** — every retained event, filterable, with a full protobuf decode of any
one you click.

### The sequence diagram

On a peer's own page: two lifelines, this node and that peer, arrows for messages
with direction and size, and connection lifecycle events as notes. A handshake
reads directly off it:

```
06:18:39.503   <- version (123 B)
06:18:39.504   -> version (102 B)
06:18:39.506   -> wtxidrelay
06:18:39.506   -> sendaddrv2
06:18:39.506   -> verack
                    119 ms
06:18:39.625   <- verack
```

Rows are spaced by how long the node waited, and the wait is written in the band
it created. A fixed pitch draws a two-second silence exactly like two messages in
the same millisecond, which is the one thing a sequence diagram is for.

Anything under ten milliseconds does not split at all. Timestamps have
millisecond resolution and Bitcoin Core batches its sends, so a gap of a few
milliseconds is the same instant as far as any of this is concerned, and prising
two rows apart to write "2 ms" between them says nothing. Above that the scale is
logarithmic, since the gaps run from ten milliseconds to minutes; it has a floor,
so a band always has room for the figure that labels it; and a ceiling, so a peer
that went quiet for an hour does not push the next message off the page. On the
sample archive that leaves a hundred rows about a sixth taller than a fixed
pitch, with twenty to thirty of the gaps carrying a figure rather than half.


The actors stay put while the messages scroll under them: the diagram is two
SVGs stacked in one scroller, a sticky one holding the column headings and the
actor boxes, and a tall one holding the messages. They share a width, so
scrolling sideways keeps the lanes lined up without anything having to
synchronise them. The lanes are sized from the panel rather than fixed, so with
only two of them the diagram fills the space it has -- 360 px lanes in a 900 px
panel where it used to draw 250 and leave the rest empty.

This is peer-observer issue #397, done in the browser rather than by exporting to
an external diagram tool.

Requests are linked to the replies they caused. A bracket in the left margin
spans an exchange — `getaddr` to the `addr` that answers it, `inv` to `getdata`
to the `tx` it fetched, `version` to `verack`, `ping` to `pong`, `cmpctblock` to
`getblocktxn` to `blocktxn`, and the BIP157 filter messages — and the reply
carries how long the peer took. A request answered by many messages, like one
`getdata` pulling down thirty transactions, gets a single bracket with a tick per
reply. Hovering either end lights up the whole exchange.

These links are inferred, and the view says so. The archive records a message's
command, direction, size and time, but not the txids, block hashes or ping nonces
inside it, so a tie is the nearest matching unanswered request rather than a
proven pairing. It is as good as certain for the handshake, for pings and for the
BIP157 messages, which are only ever sent in reply to something; it can mislink
where a reply also arrives unsolicited, which `inv`, `headers`, `addr` and
`cmpctblock` all do. Exchanges are matched within one screenful, so one spanning
a page boundary is not drawn. The toggle in the toolbar turns them off.

**Peer** — a page for one peer, reached by clicking it anywhere it appears. Its
own timeline, scoped to that peer's connection rather than to the archive, so a
peer connected for five minutes of a three-hour capture is a readable chart
instead of a sliver; its message mix by command; its connection lifecycle; its
relay record; and its message sequence diagram.

Navigation is the browser's own history: opening a peer pushes an entry, and
Back returns to the list. Routes live only as long as the session does — the
archive is dropped in rather than fetched, so a reloaded page has nothing to
show and any route in the URL is ignored on arrival.

The peer list and each peer's page name the client the peer says it is running,
taken from the `version` message it sent, or from a `getpeerinfo` snapshot where
the archive has RPC polls but not the P2P messages. The version message wins
when both are there: it is what the peer actually put on the wire, and the RPC
poll is Bitcoin Core repeating it back later. The **clients** view on the Peers
tab tallies them.

Agent strings are interned, which is the difference between a few hundred bytes
and thirty megabytes: the sample churn archive names 167,919 peers using 242
distinct strings.

A peer with no client string was usually already connected when the capture
started, so the handshake that would have named it predates the archive. The
peer page says so rather than leaving a blank. On the sample archive that
accounts for 107 of the 130 unnamed peers, and none of the 130 has an inbound
version message that was somehow missed.

**Activity** — every peer at once: one row per peer, one column per pixel of
time, a mark for the messages exchanged in each slice. Inbound sits above the
row's line and outbound below it, shaded by how many (or by how many bytes),
and connection events are vertical ticks spanning the row. Sorted by first
connection it draws the shape of a node's peer turnover; sorted by traffic it
puts the peers that matter at the top.

Above the raster, how long connections lasted, one panel per connection type and
a filter for how they ended. It sits there because it is the raster's own data
collapsed, and because it is what makes the duration filter underneath it
legible. On the sample churn archive:

```
inbound              n=1,210,406   median   580 ms   p90  987 ms   max 243 h
outbound-full-relay  n=      160   median   1.7 s    p90 16.4 s    max 167 h
block-relay-only     n=       59   median  43.1 s    p90  1.1 m    max 1.2 m
```

Small multiples rather than one chart with the types overlaid: the counts differ
by four orders of magnitude, so a shared vertical scale would flatten every
panel but the first. The horizontal scale is shared, because where each type's
mass sits on the same axis of time is the comparison worth making.

Lifetimes come from Bitcoin Core's own account of them -- the close and evict
tracepoints carry the time the connection was established -- not from the span
of events this tool happened to see, and they are accumulated during ingest
because the per-peer lifecycle list is capped and would have thrown most of them
away.

Peers are filtered by how long they stayed connected, because they have to be:
the sample archive of a churning node holds 587,383 peers, of which 562 lasted a
minute. Drawing a row each would be a solid block.

The raster is built by scanning the retained events on each redraw — around
40 ms for two and a half million — rather than kept as an aggregate during
ingest, which would cost peers times bins of memory for a view most archives
never open. That does mean it covers only the events retention kept, and it says
so when that is not all of them.

**Relay** — every transaction reaches a node more than once, and this is what
that costs. It leads with the share of received transaction bytes that were
bytes already held, because that number decides whether the rest is worth
reading:

```
wasted        21.5%     3.2 MB of 14.9 MB received
transactions  40,392    announced 1,037,820 times by 96 peers
downloaded    49,360    15,674 already held
typical wait  3.6 s     from first hearing to holding
```

Then the scorecard: which peers announced first, how often they were the first
of their own announcements, and what the late ones cost. A peer connected longer
wins more races by being there, so the rate beside the count is what makes two
comparable — on the sample archive one peer wins 57.7% of its announcements for
4 kB of waste, and another wins 11.5% for 339 kB.

**Exchanges** — what happened when either side asked the other for something:
requests of each kind sent, answered, unanswered, and how long the answers took,
in each direction. Selecting a row shows that kind's reply times.

### What the request/reply numbers do and do not mean

Requests are paired with replies by command, direction and timing. The archive
records no txids, block hashes or ping nonces, so a pairing is the nearest
matching unanswered request rather than a proven one, and three things follow
that the views state rather than paper over:

- **An announcement is not a request.** A node asks for a fraction of what it is
  told about, so an `inv` with no `getdata` after it is a choice, not a failure.
  Announcements are never counted as unanswered.
- **Pipelining makes silence unreadable.** Core keeps several `getdata` in
  flight; a later one says nothing about an earlier one. Those requests are
  reported as *unclear* rather than being guessed at either way.
- **A reply type that was never captured is not a peer going silent.** An
  archive holding `version` but no `verack` makes every handshake look
  unanswered. Since the header records the capture filter only as far as
  `low_data`, the viewer checks whether the answering command appears anywhere
  in the archive at all, and shows *not captured* instead of a number that would
  certainly be wrong.

Reply times are kept per request kind across every peer, rather than per peer.
One number per peer would have to fold a ping round trip together with a
`getaddr` that Core answers on a thirty-second timer, and that mixture means
nothing; split by request kind, each row is one comparable thing. Selecting a
row shows how long that kind took, in each direction:

```
getdata     sent 584,348   answered 575,925   peers  p50 488 ms
                                              this node  p50 1 ms
```

Tracking is bounded: two million distinct transaction hashes, after which the
view says tracking stopped and the figures cover the part of the archive it
reached.

### The ASN database

The networks view needs two things the rest of the page does not:
[asmap](https://github.com/0xB10C/asmap) needs Bitcoin Core's trie (~1.5 MB,
fetched by `build.sh` into `web/asmap.dat`), and
[asinfo](https://github.com/0xB10C/asinfo) embeds AS names at compile time, which
is around 4 MB — more than the entire rest of the viewer.

So AS naming is its own WebAssembly module, and both it and the trie load only
when the networks view is first opened. The main bundle stays at 0.36 MB
gzipped; the ASN database costs about 3 MB, once, and only if you ask for it.
## Building

Everything comes from the Nix dev shell:

```sh
git clone --recurse-submodules <this repo>
cd archive-viewer-peer-observer
nix develop
./build.sh --serve      # build the wasm bundle and serve web/ on :8080
```

`./build.sh` alone just builds into `web/pkg/`. The page must be served over
HTTP — ES modules and WebAssembly cannot be fetched from a `file://` URL.

If you cloned without submodules, the build will tell you to run
`git submodule update --init`.

### Tests

```sh
cargo test --workspace
PEER_OBSERVER_ARCHIVE=/path/to/real.bin.zst cargo test --workspace
```

Fixtures are synthesised rather than captured: a real archive contains the peer
addresses of whoever's node produced it, which has no place in a public repo. Set
`PEER_OBSERVER_ARCHIVE` to also run the suite against a genuine archive of your
own.

## Layout

| path | what it is |
|---|---|
| `crates/core` | decoding, classification, aggregation, JSON views; pure Rust, builds native and for wasm32 |
| `crates/wasm` | the `wasm-bindgen` boundary — thin, everything crossing it is JSON |
| `crates/asinfo-wasm` | ASN name tables; a second module, loaded only for the networks view |
| `web/index.html` | the whole UI: markup, styles and script in one file |
| `peer-observer/` | git submodule, pinned; the protobuf schema is compiled from it |

The protobuf schema is compiled from the submodule's `.proto` files with the same
`prost-build` configuration peer-observer's own `shared/build.rs` uses, so the
generated types match upstream exactly. Depending on the `shared` crate directly
is not possible: it pulls in `async-nats`, `tokio`, `prometheus`, `clap` and
`bitcoind` with the `download` feature, none of which build for
`wasm32-unknown-unknown`.

To follow a schema change upstream, bump the submodule:

```sh
git -C peer-observer fetch origin master && git -C peer-observer checkout <rev>
git add peer-observer && cargo test --workspace
```

## The archive format

Written by peer-observer's `tools/archive`. Each file is a single zstd stream
(or raw bytes with `--compression-level 0`) of varint-length-delimited protobuf
messages:

```
[varint len][ header.ArchiveHeader ]   <- exactly one, first
[varint len][ event.Event ]            <- repeated to EOF
...
```

There is no frame checksum, no declared uncompressed size and only one zstd frame
per file, so decoding is strictly front-to-back and progress can only be measured
in compressed bytes. Filenames are `<base>.<YYYYMMDD-HHMMSS-mmm>.bin[.zst]`, where
the base is free text that may itself contain dots — so the timestamp is matched
from the right, never by splitting on the first dot.

### Truncated archives

An archive that is still being written ends mid-frame. Every record before the
cut is valid, so the viewer treats truncation as information rather than an error.

This takes some care. `ruzstd` withholds the last `window_size` decompressed bytes
for back-references until the frame's final block arrives, and these archives
declare a 128 MiB window — which for any archive smaller than that is *all* of it.
The decoder therefore hands the frame a synthetic empty final block at EOF to
release the tail; see `crates/core/src/decode.rs`.

The only genuinely unrecoverable part is a partial zstd block at the very end (up
to 128 kB), which is not decodable even in principle. For comparison, the `zstd`
CLI discards a further whole block in this situation.

## Notes on the implementation

**Is zstd in WebAssembly fast enough?** Yes, comfortably. Measured end to end
through the wasm boundary in V8 on a live archive: 58 MB decompressed, 614,483
events decoded, classified, aggregated and indexed in 0.50 s (~117 MB/s). The
pure-Rust `ruzstd` needs no C fallback, which keeps the build free of a wasm C
toolchain.

**The timeline** is an adaptive histogram: an archive's time range is not known
until its last event, so it starts at 100 ms bins and halves its resolution
whenever it would exceed 4096 bins. Counts stay exact in constant memory with no
second pass. Counts are kept per event kind rather than per group, so a group can
be broken down by type -- the connection rate by inbound/outbound/closed/evicted --
over the whole archive rather than only over the retained events.

**Memory.** A wasm32 module has a 4 GiB address space and browsers allow rather
less, and an allocation failure aborts the module outright: the browser reports
`unreachable executed`, and every later call fails with "recursive use of an
object detected". Four things keep that from happening. Event bytes go into
fixed-size chunks rather than one growing buffer, so reaching a 512 MB budget
never needs a ~1.5 GB transient to double through. Every store allocation is
fallible, so exhaustion stops retention instead of the module. Raw transaction
and block payloads are dropped, which is the single biggest win. And the peer
table, which sits outside the budget, caps its per-peer connection lifecycle list
while keeping an exact count.

Measured on a synthetic full-data archive -- 3.4 GB decompressed, 400,000 `tx`
messages carrying raw transactions: all 400,000 events retained in 59 MB, peak
RSS 261 MB, 3.33 GB of payload dropped.

**The event inspector** decodes the selected event against an embedded
`FileDescriptorSet` using `prost-reflect`, rather than matching on the schema's
~60 message types by hand. Field names come from the schema, so new upstream
message types appear without any change here. Bytes fields render as hex, since
they are txids, block hashes and raw transactions.

**Colours.** The eight event groups use a fixed categorical palette validated in
both light and dark against adjacent-pair colour-vision-deficiency and
normal-vision separation floors. The legend carries each group's total, so series
identity never rests on colour alone.
