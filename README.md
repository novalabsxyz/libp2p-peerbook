# libp2p-peerbook

[![Build status](https://badge.buildkite.com/484cb26ebc1dd62f4003e4c20a70486b324074e7a1dee53b96.svg)](https://buildkite.com/helium/libp2p-peerbook)
[![codecov](https://codecov.io/gh/helium/libp2p-peerbook/branch/master/graph/badge.svg)](https://codecov.io/gh/helium/libp2p-peerbook)
[![Hex.pm](https://img.shields.io/hexpm/v/libp2p-peerbook)](https://hex.pm/packages/libp2p-peerbook)

This is a library for storing libp2p peer information in a peer to
peer (p2p) network. The peerbook plays a key role in a p2p network
because it maintains a view over time of the peers that are available
in the network.

## Features/Options

The following key features define what a peerbook does with the peer
records it maintains:

### The self record

The *self** record is the peer record defined by the public key binary
passed into the peerbook using the requires `pubkey_bin` option when
it is started.

The self peer record can not be updated through an API but is updated
on a regular schedule.  To be able to sign the peer record the
peerbook requires a signing function passed in with the `sig_fun`
option.

To affect the data that goes into the self record use the `set_` and
`register_` functions in the peerbook API.

### Record expiration

Peer records in the peerbook are expired after a configurable
`stale_time` after which the record is no longer retrievable from the
peerbook

### Change notification

Local peer change notification. When the self record changes or any
new records are put in the store the peerbook will send a local
notification `{changed_peers, ChangeTuple}` with all the add and
removed peers since the last notification. To set the rate of
notifications, the `notification_time` option can be used.

### Signed metadata

Metadata can be associated with the self peer and is included in the
signed peer record. The `metadata_fun`option can be used to supply a
function that is called every time the self peer is updated by the
peerbook.

### Network ID

The peerbook will only accept peer records that have the same
`network_id` as the peerbook is configured with. This allows multiple
overlapping swarms to run without affecting each other by using
different network ids.

**Note:** The default network id allows peer records from any
host. Set the network id before actually using a peerbook in a
production network.

## Using the library

Add the library to your `rebar.config` deps section:

```erlang
{deps, [
        libp2p_peerbook,
        ...
       ]}.
```

## Creating a peerbook instance

Usually a peerbook is created as part of a libp2p swarm instance,
which ends up using something similar to:

```erlang
    #{public := PubKey, secret := PrivKey} = libp2p_crypto:generate_keys(ecc_compact),
    SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
    Opts = #{
        pubkey_bin => PubKeyBin,
        sig_fun => SigFun,
    },
    {ok Pid} = libp2p_peerbook:start_link(Opts),
    Handle = libp2p_peerbook:peerbook_handle(Pid)
```

Since a peerbook is representing a host on a network that host is
identified by a public key, and its binary form `PubKeyBin`. Since the
peer entry for the host is signed the options also need to include a
`SigFun` so that the peerbook can update the peer record for this
host.

The final step is to retrieve the `Handle` of the peerbook. Peerbook
functions all go through a handle to allow concurrency optimizations.

## Getting peers

Fetch a peer record from the peerbook:

```erlang
    {ok, Peer} = libp2p_peerbook:get(Handle, PeerID)
```

where `PeerID` is the binary of the public key of a peer.

The peerbook will return `{error, not_found}`if the record is not
found in the store or has gone stale.

## Putting peers

Put a peer recors in the store using:

```erlang
    libp2p_peerbook:put(Handle, Peer)
```

Where `Peer` is a signed peer record. The peerbook will validate the
peer against a number of criteria including verifying the signature,
whether the peer is stale and supersedes an existing entry and that
the network id is acceptable.

Any peers passing validation will be stored and sent out on the next
local notification. An errir is returned for Invalid peers.

## Notifications

When the peerbook updates the self record or new peer entries are
stored the peerbook will send out a notification to a `pg2` group to
notify of the new or changed peers.

To join the group:

```erlang
    libp2p_peerbook:join_notify(Handle, self())
```

After which the process `Pid` will receive messages with the following
format:

```erlang
    {changed_peers, { {add, AddMap}, {remove,RemoveSet} }}
```

Where `AddMap` is a map of peer public key binaries to peers and
`RemoveSet` is a set of removed peer public key binaries.
