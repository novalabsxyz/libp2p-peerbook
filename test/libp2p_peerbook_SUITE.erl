-module(libp2p_peerbook_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

all() ->
    [
     listen_addr_test,
     session_test,
     nat_type_test,
     get_put_test,
     blacklist_test,
     heartbeat_test,
     notify_test,
     stale_test
    ].


start_peerbook(OptOverride, Config) ->
    #{public := PubKey, secret := PrivKey} = libp2p_crypto:generate_keys(ecc_compact),
    SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
    PubKeyBin = libp2p_crypto:pubkey_to_bin(PubKey),
    DataDir = ?config(priv_dir, Config),
    Opts = maps:merge(#{ pubkey_bin => PubKeyBin,
                         data_dir => DataDir,
                         sig_fun => SigFun },
                      OptOverride),
    {ok, Pid} = libp2p_peerbook:start_link(Opts),
    {ok, Handle} = libp2p_peerbook:peerbook_handle(Pid),
    [{peerbook, Handle}, {pubkey_bin, PubKeyBin} | Config].


init_per_testcase(heartbeat_test, Config) ->
    %% have the peer refresh itself quickly and send out notifications
    %% quick
    start_peerbook(#{peer_time => 20,
                     notify_time => 20}, Config);
init_per_testcase(notify_test, Config) ->
    %% only send out notifications quickly
    start_peerbook(#{notify_time => 20}, Config);
init_per_testcase(stale_test, Config) ->
    %% Set stale time to something short
    StaleTime = 50,
    [{stale_time, StaleTime} |
     start_peerbook(#{stale_time => StaleTime}, Config)];
init_per_testcase(_, Config) ->
    start_peerbook(#{}, Config).

end_per_testcase(_, Config) ->
    Handle = ?config(peerbook, Config),
    gen_server:stop(libp2p_peerbook:peerbook_pid(Handle)),
    ok.

-define(assertAsync(Expr, BoolExpr),
        case test_util:wait_until(fun() -> (Expr),(BoolExpr) end) of
            true -> ok;
            false -> erlang:error({assert,
                                   [{module, ?MODULE},
                                    {line, ?LINE},
                                    {expression, (??BoolExpr)},
                                    {expected, true},
                                    {value ,false}
                                   ]
                                  })
        end).

nat_type_test(Config) ->
    Handle = ?config(peerbook, Config),
    PubKeyBin = ?config(pubkey_bin, Config),

    %% Set nat type
    libp2p_peerbook:set_nat_type(Handle, symmetric),
    ?assertAsync({ok, ThisPeer} = libp2p_peerbook:get(Handle, PubKeyBin),
                 symmetric == libp2p_peer:nat_type(ThisPeer)),

    ok.

listen_addr_test(Config) ->
    Handle = ?config(peerbook, Config),
    PubKeyBin = ?config(pubkey_bin, Config),

    %% confirm empty listen addrs
    {ok, ThisPeer0} = libp2p_peerbook:get(Handle, PubKeyBin),
    ?assertEqual([], libp2p_peer:listen_addrs(ThisPeer0)),

    %% register a listen address
    ListenAddr = "/ip4/8.8.8.8/tcp/1234",
    libp2p_peerbook:register_listen_addr(Handle, ListenAddr),
    %% confirm it's stored
    ?assertAsync({ok, ThisPeer} = libp2p_peerbook:get(Handle, PubKeyBin),
                 [ListenAddr] == libp2p_peer:listen_addrs(ThisPeer)),

    %% unregister the listen address
    libp2p_peerbook:unregister_listen_addr(Handle, ListenAddr),
    %% confirm it's cleared
    ?assertAsync({ok, Peer} = libp2p_peerbook:get(Handle, PubKeyBin),
                 [] == libp2p_peer:listen_addrs(Peer)),

    ok.

session_test(Config) ->
    Handle = ?config(peerbook, Config),
    PubKeyBin = ?config(pubkey_bin, Config),

    %% confirm empty listen addrs
    {ok, ThisPeer} = libp2p_peerbook:get(Handle, PubKeyBin),
    ?assertEqual([], libp2p_peer:connected_peers(ThisPeer)),

    %% register a session key.. just reuse the one we already have
    libp2p_peerbook:register_session(Handle, PubKeyBin, self()),

    %% confirm it's stored
    ?assertAsync({ok, Peer} = libp2p_peerbook:get(Handle, PubKeyBin),
                 [PubKeyBin] == libp2p_peer:connected_peers(Peer)),

    %% unregister the session address
    libp2p_peerbook:unregister_session(Handle, self()),
    %% confirm it's cleared
    ?assertAsync({ok, Peer} = libp2p_peerbook:get(Handle, PubKeyBin),
                 [] == libp2p_peer:connected_peers(Peer)),

    ok.


get_put_test(Config) ->
    Handle = ?config(peerbook, Config),
    PubKeyBin = ?config(pubkey_bin, Config),

    {ok, ThisPeer} = libp2p_peerbook:get(Handle, PubKeyBin),
    ?assertEqual(PubKeyBin, libp2p_peer:pubkey_bin(ThisPeer)),

    %% Add a peer beyond the self peer
    {ok, NewPeer} = mk_peer(#{}),
    libp2p_peerbook:put(Handle, [NewPeer]),

    %% Check is_key for self adnd new peer
    ?assert(libp2p_peerbook:is_key(Handle, PubKeyBin)),
    ?assert(libp2p_peerbook:is_key(Handle, libp2p_peer:pubkey_bin(NewPeer))),
    %% And fail to fetch a non-existent key
    ?assertNot(libp2p_peerbook:is_key(Handle, <<>>)),

    %% Check that self and new peer are in the store
    ?assertEqual(2, length(libp2p_peerbook:keys(Handle))),
    ?assertEqual(2, length(libp2p_peerbook:values(Handle))),

    %% removing self should fail
    ?assertMatch({error, _}, libp2p_peerbook:remove(Handle, PubKeyBin)),
    %% check removing other peer
    ?assertEqual(ok, libp2p_peerbook:remove(Handle, libp2p_peer:pubkey_bin(NewPeer))),
    ?assertNot(libp2p_peerbook:is_key(Handle, libp2p_peer:pubkey_bin(NewPeer))),
    ?assertEqual(1, length(libp2p_peerbook:keys(Handle))),

    ok.

blacklist_test(Config) ->
    Handle = ?config(peerbook, Config),

    BlackListAddr = "/ip4/9.9.9.9/tcp/4321",
    ListenAddrs = [BlackListAddr, "/ip4/8.8.8.8/tcp/1234"],
    %% Add a peer beyond the self peer
    {ok, NewPeer} = mk_peer(#{listen_addrs => ListenAddrs}),
    libp2p_peerbook:put(Handle, [NewPeer]),

    %% black list an address
    libp2p_peerbook:blacklist_listen_addr(Handle, libp2p_peer:pubkey_bin(NewPeer), BlackListAddr),
    %% check that it's no longer in the cleared listen addresses for the peer
    ?assertAsync({ok, Peer} = libp2p_peerbook:get(Handle, libp2p_peer:pubkey_bin(NewPeer)),
                 not lists:member(BlackListAddr, libp2p_peer:cleared_listen_addrs(Peer))),

    %% blacklisting for an unkown peer returns an error
    ?assertMatch({error, not_found}, libp2p_peerbook:blacklist_listen_addr(Handle, <<>>, BlackListAddr)),

    ok.


heartbeat_test(Config) ->
    Handle = ?config(peerbook, Config),
    PubKeyBin = ?config(pubkey_bin, Config),

    libp2p_peerbook:join_notify(Handle, self()),
    %% joining twise is fine
    libp2p_peerbook:join_notify(Handle, self()),

    receive
        {new_peers, [Peer]} ->
            ?assertEqual(PubKeyBin, libp2p_peer:pubkey_bin(Peer))
    after 1000 ->
            ct:fail(timeout_heartbeat)
    end,

    ok.

notify_test(Config) ->
    Handle = ?config(peerbook, Config),
    PubKeyBin = ?config(pubkey_bin, Config),

    libp2p_peerbook:join_notify(Handle, self()),
    %% cause a change in the peer
    libp2p_peerbook:set_nat_type(Handle, static),

    receive
        {new_peers, [Peer]} ->
            ?assertEqual(PubKeyBin, libp2p_peer:pubkey_bin(Peer))
    after 1000 ->
            ct:fail(timeout_notify)
    end,

    ok.

stale_test(Config) ->
    Handle = ?config(peerbook, Config),
    StaleTime = ?config(stale_time, Config),

    %% Ensure stale time is what we configured it as
    ?assertEqual(StaleTime, libp2p_peerbook:stale_time(Handle)),

    %% Add a peer
    {ok, NewPeer} = mk_peer(#{}),
    libp2p_peerbook:put(Handle, [NewPeer]),
    ?assert(libp2p_peerbook:is_key(Handle, libp2p_peer:pubkey_bin(NewPeer))),

    %% Wait for it to get stale and no longer be gettable
    ?assertAsync(Result = libp2p_peerbook:get(Handle, libp2p_peer:pubkey_bin(NewPeer)),
                 Result == {error, not_found}),

    ok.

%%
%% Utilities
%%

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
