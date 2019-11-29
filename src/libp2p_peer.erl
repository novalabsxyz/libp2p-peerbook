%% @copyright Helium Systems, Inc.
%%
%% @doc A peeer record represents the current state of a peer on the libp2p network.
-module(libp2p_peer).

-include("pb/libp2p_peer_pb.hrl").

-type nat_type() :: libp2p_peer_pb:nat_type().
-type peer_map() :: #{ pubkey_bin => libp2p_crypto:pubkey_bin(),
                       listen_addrs => [string()],
                       connected => [binary()],
                       nat_type => nat_type(),
                       network_id => binary(),
                       signed_metadata => #{binary() => binary()}
                     }.
-type peer() :: #libp2p_signed_peer_pb{}.
-type metadata() :: [{string(), binary()}].
-export_type([peer/0, peer_map/0, nat_type/0]).

-export([from_map/2, encode/2, decode/1, verify/1,
         pubkey_bin/1, listen_addrs/1, connected_peers/1, nat_type/1, timestamp/1,
         supersedes/2, is_stale/2, network_id/1, network_id_allowable/2]).
%% signed metadata
-export([signed_metadata/1, signed_metadata_get/3]).
%% metadata (unsigned!)
-export([metadata/1, metadata_set/2, metadata_put/3, metadata_get/3]).
%% blacklist (unsigned!)
-export([blacklist/1, is_blacklisted/2,
         blacklist_set/2, blacklist_add/2,
         cleared_listen_addrs/1]).

%% @doc Create a signed peer from a given map of fields.
-spec from_map(peer_map(), fun((binary()) -> binary())) -> {ok, peer()} | {error, term()}.
from_map(Map, SigFun) ->
    Timestamp = case maps:get(timestamp, Map, no_entry) of
                    no_entry -> erlang:system_time(millisecond);
                    V -> V
                end,
    Peer = #libp2p_peer_pb{pubkey=maps:get(pubkey_bin, Map),
                           listen_addrs=[multiaddr:new(L) || L <- maps:get(listen_addrs, Map)],
                           connected = maps:get(connected, Map, []),
                           nat_type=maps:get(nat_type, Map),
                           network_id=maps:get(network_id, Map, <<>>),
                           timestamp=Timestamp},
    case encode_map(maps:get(signed_metadata, Map, #{})) of
        {error, Error} ->
            {error, Error};
        {ok, MD} ->
            sign_peer(Peer#libp2p_peer_pb{signed_metadata = MD}, SigFun)
    end.

%% @doc Gets the public key for the given peer.
-spec pubkey_bin(peer()) -> libp2p_crypto:pubkey_bin().
pubkey_bin(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{pubkey=PubKeyBin}}) ->
    PubKeyBin.

%% @doc Gets the list of peer multiaddrs that the given peer is
%% listening on.
-spec listen_addrs(peer()) -> [string()].
listen_addrs(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{listen_addrs=Addrs}}) ->
    [multiaddr:to_string(A) || A <- Addrs].

%% @doc Gets the list of peer crypto addresses that the given peer was last
%% known to be connected to.
-spec connected_peers(peer()) -> [libp2p_crypto:pubkey_bin()].
connected_peers(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{connected=Conns}}) ->
    Conns.

%% @doc Gets the NAT type of the given peer.
-spec nat_type(peer()) -> nat_type().
nat_type(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{nat_type=NatType}}) ->
    NatType.

%% @doc Gets the timestamp of the given peer.
-spec timestamp(peer()) -> integer().
timestamp(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{timestamp=Timestamp}}) ->
    Timestamp.

%% @doc Gets the signed metadata of the given peer
-spec signed_metadata(peer()) -> map().
signed_metadata(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{signed_metadata=undefined}}) ->
    #{};
signed_metadata(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{signed_metadata=MD}}) ->
    lists:foldl(fun({K, #libp2p_metadata_value_pb{value = {_Type, V}}}, Acc) ->
                     maps:put(list_to_binary(K), V, Acc)
             end, #{}, MD).

%% @doc Gets a key from the signed metadata of the given peer
-spec signed_metadata_get(peer(), Key::binary(), Default::any()) -> any().
signed_metadata_get(Peer, Key, Default) ->
    maps:get(Key, signed_metadata(Peer), Default).

%% @doc Gets the metadata map from the given peer. The metadata for a
%% peer is `NOT' part of the signed peer since it can be read and
%% updated by anyone to annotate the given peer with extra information
-spec metadata(peer()) -> metadata().
metadata(#libp2p_signed_peer_pb{metadata=Metadata}) ->
    Metadata.

%% @doc Replaces the full metadata for a given peer
-spec metadata_set(peer(), metadata()) -> {ok, peer()} | {error, term()}.
metadata_set(Peer=#libp2p_signed_peer_pb{}, Metadata) when is_list(Metadata) ->
    {ok, Peer#libp2p_signed_peer_pb{metadata=Metadata}}.

%% @doc Updates the metadata for a given peer with the given key/value
%% pair. The `Key' is expected to be a string, while `Value' is
%% expected to be a binary.
-spec metadata_put(peer(), string(), binary()) -> {ok, peer()} | {error, term()}.
metadata_put(Peer=#libp2p_signed_peer_pb{}, Key, Value) when is_list(Key), is_binary(Value) ->
    Metadata = lists:keystore(Key, 1, metadata(Peer), {Key, Value}),
    metadata_set(Peer, Metadata).

%% @doc Gets the value for a stored `Key' in metadata. If not found,
%% the `Default' is returned.
-spec metadata_get(peer(), Key::string(), Default::any()) -> any().
metadata_get(Peer=#libp2p_signed_peer_pb{}, Key, Default) ->
    case lists:keyfind(Key, 1, metadata(Peer)) of
        false -> Default;
        {_, Value} -> Value
    end.

%% @doc Returns whether a given `Target' is more recent than `Other'
-spec supersedes(Target::peer(), Other::peer()) -> boolean().
supersedes(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{timestamp=ThisTimestamp}},
           #libp2p_signed_peer_pb{peer=#libp2p_peer_pb{timestamp=OtherTimestamp}}) ->
    ThisTimestamp > OtherTimestamp.

%% @doc Returns the declared network id for the peer, if any
-spec network_id(peer()) -> binary() | undefined.
network_id(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{network_id = <<>>}}) ->
    undefined;
network_id(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{network_id=ID}}) ->
    ID.

%% @doc Returns whether a givne network id is compatible with this peer.
%%
%% A network id is compatible with the network id of this peer if they
%% are equal or if either of them is `undefined'
network_id_allowable(Peer, MyNetworkID) ->
    network_id(Peer) == MyNetworkID
    orelse libp2p_peer:network_id(Peer) == undefined
    orelse MyNetworkID == undefined.

%% @doc Returns whether a given peer is stale relative to a given
%% stale delta time in milliseconds.
-spec is_stale(peer(), integer()) -> boolean().
is_stale(#libp2p_signed_peer_pb{peer=#libp2p_peer_pb{timestamp=Timestamp}}, StaleMS) ->
    Now = erlang:system_time(millisecond),
    (Timestamp + StaleMS) < Now.

%% @doc Gets the blacklist for this peer. This is a metadata based
%% feature that enables listen addresses to be blacklisted so they
%% will not be connected to until that address is removed from the
%% blacklist.
-spec blacklist(peer()) -> [string()].
blacklist(Peer=#libp2p_signed_peer_pb{}) ->
    case metadata_get(Peer, "blacklist", false) of
        false -> [];
        Bin -> binary_to_term(Bin)
    end.

%% @doc Returns whether a given listen address is blacklisted. Note
%% that a blacklisted address may not actually appear in the
%% listen_addrs for this peer.
-spec is_blacklisted(peer(), string()) -> boolean().
is_blacklisted(Peer=#libp2p_signed_peer_pb{}, ListenAddr) ->
   lists:member(ListenAddr, blacklist(Peer)).

%% @doc Sets the blacklist for a given peer. Note that currently no
%% validation is done against the existing listen addresses stored in
%% the peer. Blacklisting an address that the peer is not listening to
%% will have no effect anyway.
-spec blacklist_set(peer(), [string()]) -> {ok, peer()} | {error, term()}.
blacklist_set(Peer=#libp2p_signed_peer_pb{}, BlackList) when is_list(BlackList) ->
    metadata_put(Peer, "blacklist", term_to_binary(BlackList)).

%% @doc Add a given listen address to the blacklist for the given
%% peer.
-spec blacklist_add(#libp2p_signed_peer_pb{}, ListenAddr::string()) -> {ok, peer()} | {error, term()}.
blacklist_add(Peer=#libp2p_signed_peer_pb{}, ListenAddr) ->
    BlackList = blacklist(Peer),
    NewBlackList = case lists:member(ListenAddr, BlackList) of
                       true -> BlackList;
                       false -> [ListenAddr | BlackList]
                   end,
    blacklist_set(Peer, NewBlackList).

%% @doc Returns the listen addrs for this peer filtered using the
%% blacklist for the peer, if one is present. This is just a
%% convenience function to clear the listen adddresses for a peer
%% with the blacklist stored in metadata.
-spec cleared_listen_addrs(peer()) -> [string()].
cleared_listen_addrs(Peer=#libp2p_signed_peer_pb{}) ->
    sets:to_list(sets:subtract(sets:from_list(listen_addrs(Peer)),
                               sets:from_list(blacklist(Peer)))).


%% @doc Encodes the given peer into its binary form. The peer is
%% stripped from its metadata before encoding if `Strip' is `true'.
-spec encode(peer(), Strip::boolean()) -> binary().
encode(Msg=#libp2p_signed_peer_pb{}, true) ->
    {ok, Stripped} = metadata_set(Msg, []),
    libp2p_peer_pb:encode_msg(Stripped);
encode(Msg=#libp2p_signed_peer_pb{}, false) ->
    libp2p_peer_pb:encode_msg(Msg).

%% @doc Decodes a given binary into a peer. Note that a decoded peer
%% may not verify, so ensure to call `verify' before actually using
%% peer content
-spec decode(binary()) -> {ok, peer()} | {error, term()}.
decode(Bin) ->
    {ok, libp2p_peer_pb:decode_msg(Bin, libp2p_signed_peer_pb)}.

%% @doc Cryptographically verifies a given peer and it's
%% associations. Returns true if the given peer can be verified, false
%% otherwise.
-spec verify(peer()) -> boolean().
verify(Msg=#libp2p_signed_peer_pb{peer=Peer0=#libp2p_peer_pb{signed_metadata=MD}, signature=Signature}) ->
    Peer = Peer0#libp2p_peer_pb{signed_metadata=lists:usort(MD)},
    EncodedPeer = libp2p_peer_pb:encode_msg(Peer),
    PubKey = libp2p_crypto:bin_to_pubkey(pubkey_bin(Msg)),
    libp2p_crypto:verify(EncodedPeer, Signature, PubKey).

%%
%% Internal
%%

-spec sign_peer(#libp2p_peer_pb{}, libp2p_crypto:sig_fun()) -> {ok, peer()} | {error, term()}.
sign_peer(Peer0 = #libp2p_peer_pb{signed_metadata=MD}, SigFun) ->
    Peer = Peer0#libp2p_peer_pb{signed_metadata=lists:usort(MD)},
    EncodedPeer = libp2p_peer_pb:encode_msg(Peer),
    case SigFun(EncodedPeer) of
        {error, Error} ->
            {error, Error};
        Signature ->
            {ok, #libp2p_signed_peer_pb{peer=Peer, signature=Signature}}
    end.

encode_map(Map) ->
    Encode = fun(_, _, {error, Error}) ->
                     {error, Error};
                 (K, V,  Acc) when is_binary(K), is_integer(V) ->
                     [{binary_to_list(K), #libp2p_metadata_value_pb{value = {int, V}}}|Acc];
                (K, V, Acc) when is_binary(K), is_float(V) ->
                     [{binary_to_list(K), #libp2p_metadata_value_pb{value = {flt, V}}}|Acc];
                (K, V, Acc) when is_binary(K), is_binary(V) ->
                     [{binary_to_list(K), #libp2p_metadata_value_pb{value = {bin, V}}}|Acc];
                (K, V, Acc) when is_binary(K), (V == true orelse V == false) ->
                     [{binary_to_list(K), #libp2p_metadata_value_pb{value = {boolean, V}}}|Acc];
                (K, V, _Acc) when is_binary(K) ->
                     {error, {invalid_value, V}};
                (K, _V, _Acc) ->
                     {error, {invalid_key, K}}
             end,
    case maps:fold(Encode, [], Map) of
        {error, Error} -> {error, Error};
        List -> {ok, lists:sort(List)}
    end.


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

mk_peer(MapOveride) ->
    #{public := PubKey, secret := PrivKey} = libp2p_crypto:generate_keys(ecc_compact),
    SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
    mk_peer(MapOveride, libp2p_crypto:pubkey_to_bin(PubKey), SigFun).

mk_peer(MapOverride, PubKeyBin, SigFun) ->
    PeerMap = maps:merge(#{pubkey_bin => PubKeyBin,
                           listen_addrs => ["/ip4/8.8.8.8/tcp/1234"],
                           nat_type => static
                          }, MapOverride),
    libp2p_peer:from_map(PeerMap, SigFun).


coding_test() ->
    #{public := PubKey2, secret := PrivKey2} = libp2p_crypto:generate_keys(ecc_compact),
    SigFun2 = libp2p_crypto:mk_sig_fun(PrivKey2),

    {ok, Peer1} = mk_peer(#{connected => [libp2p_crypto:pubkey_to_bin(PubKey2)]}),
    {ok, DecodedPeer} = libp2p_peer:decode(libp2p_peer:encode(Peer1, false)),

    %% check if decoded is the same as original
    ?assert(libp2p_peer:pubkey_bin(Peer1) == libp2p_peer:pubkey_bin(DecodedPeer)),
    ?assert(libp2p_peer:timestamp(Peer1) ==  libp2p_peer:timestamp(DecodedPeer)),
    ?assert(libp2p_peer:listen_addrs(Peer1) == libp2p_peer:listen_addrs(DecodedPeer)),
    ?assert(libp2p_peer:nat_type(Peer1) ==  libp2p_peer:nat_type(DecodedPeer)),
    ?assert(libp2p_peer:connected_peers(Peer1) == libp2p_peer:connected_peers(DecodedPeer)),
    ?assert(libp2p_peer:metadata(Peer1) == libp2p_peer:metadata(DecodedPeer)),
    ?assert(libp2p_peer:network_id(Peer1) == libp2p_peer:network_id(DecodedPeer)),
    ?assert(libp2p_peer:signed_metadata(Peer1) == libp2p_peer:signed_metadata(DecodedPeer)),

    %% Check signature verify
    ?assert(libp2p_peer:verify(Peer1)),

    %% ensure signing with a different sigfun invalidates the verify
    {ok, InvalidPeer} = mk_peer(#{}, libp2p_peer:pubkey_bin(Peer1), SigFun2),
    ?assert(not libp2p_peer:verify(InvalidPeer)),

    %% ensure timestamp override workds
    {ok, Peer2} = mk_peer(#{timestamp => 22}),
    ?assertEqual(22, libp2p_peer:timestamp(Peer2)),


    %% Try creating a peer with a sigfun that returns an error
    ?assertMatch({error, _}, mk_peer(#{}, libp2p_crypto:pubkey_to_bin(PubKey2),
                                     fun(_) -> {error, no_bueno} end)),

    ok.

blacklist_test() ->
    BlackListAddr = "/ip4/8.8.8.8/tcp/1234",
    ListenAddrs = [BlackListAddr, "/ip4/9.9.9.9/tcp/1234"],
    {ok, Peer1} = mk_peer(#{listen_addrs => ListenAddrs}),

    ?assertEqual(ListenAddrs, libp2p_peer:cleared_listen_addrs(Peer1)),

    {ok, Peer2} = libp2p_peer:blacklist_add(Peer1, BlackListAddr),
    ?assertEqual(lists:delete(BlackListAddr, ListenAddrs), libp2p_peer:cleared_listen_addrs(Peer2)),

    %% check blacklist membership
    ?assert(libp2p_peer:is_blacklisted(Peer2, BlackListAddr)),
    %% check blacklist
    ?assertEqual([BlackListAddr], libp2p_peer:blacklist(Peer2)),
    %% blacklist is deduped
    {ok, Peer3} = libp2p_peer:blacklist_add(Peer2, BlackListAddr),
    ?assertEqual([BlackListAddr], libp2p_peer:blacklist(Peer3)),

    %% Ensure metadata like blacklist is stripped on list encode
    {ok, DecodedPeer} = libp2p_peer:decode(libp2p_peer:encode(Peer2, true)),
    ?assertEqual([], libp2p_peer:blacklist(DecodedPeer)),

    ok.

network_id_test() ->
    {ok, Peer1} = mk_peer(#{}),
    {ok, Peer2} = mk_peer(#{network_id => <<"hello">>}),

    ?assertEqual(undefined, libp2p_peer:network_id(Peer1)),
    ?assertEqual(<<"hello">>, libp2p_peer:network_id(Peer2)),

    %% undefined network id is always allowed
    ?assert(libp2p_peer:network_id_allowable(Peer1, undefined)),
    ?assert(libp2p_peer:network_id_allowable(Peer2, undefined)),
    %% a network id is allowed if the peer has undefined or a matching network id
    ?assert(libp2p_peer:network_id_allowable(Peer1, <<"hello">>)),
    ?assert(libp2p_peer:network_id_allowable(Peer2, <<"hello">>)),
    ?assert(not libp2p_peer:network_id_allowable(Peer2, <<"not hello">>)),

    ok.


signed_metadata_test() ->
    MD = #{ <<"int">> => 22,
            <<"double">> => 42.2,
            <<"bytes">> => <<"hello">>,
            <<"boolean">> => true
          },
    {ok, Peer1} = mk_peer(#{signed_metadata => MD}),

    ?assertEqual(MD, libp2p_peer:signed_metadata(Peer1)),

    ?assertEqual(<<"hello">>, libp2p_peer:signed_metadata_get(Peer1, <<"bytes">>, false)),
    ?assertEqual(false, libp2p_peer:signed_metadata_get(Peer1, <<"unknown">>, false)),

    ?assertMatch({error, {invalid_key, _}}, mk_peer(#{signed_metadata => MD#{"foo" => 22}})),
    ?assertMatch({error, {invalid_value, _}}, mk_peer(#{signed_metadata => MD#{<<"foo">> => foo}})),

    ok.


stale_test() ->
    {ok, Peer1} = mk_peer(#{}),

    %% a peer is stale if it's older than x millis. 0 should really
    %% always be stale, a ways from the peer's creation time isn't
    ?assert(libp2p_peer:is_stale(Peer1, -10)),
    ?assert(not libp2p_peer:is_stale(Peer1, 10000)),

    {ok, Peer2} = mk_peer(#{}),
    ?assert(libp2p_peer:supersedes(Peer2, Peer1)),

    ok.

-endif.
