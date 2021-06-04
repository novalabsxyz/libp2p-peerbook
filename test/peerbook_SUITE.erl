-module(peerbook_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

all() ->
    [
     listen_addr_test,
     %%session_test,    test disabled as sessions are no longer to be managed here, TODO - finalise requirements here
     nat_type_test,
     get_put_test,
     blacklist_test,
     heartbeat_test,
     notify_test,
     stale_test,
     signed_metadata_test
    ].

setup() ->
    application:ensure_all_started(lager),
    lager:set_loglevel(lager_console_backend, debug),
    lager:set_loglevel({lager_file_backend, "log/console.log"}, debug),
    ok.

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
    setup(),
    %% have the peer refresh itself quickly and send out notifications
    %% quick
    start_peerbook(#{peer_time => 20,
                     notify_time => 20}, Config);
init_per_testcase(notify_test, Config) ->
    setup(),
    %% only send out notifications quickly
    start_peerbook(#{notify_time => 50}, Config);
init_per_testcase(stale_test, Config) ->
    setup(),
    %% Set stale time to something short
    StaleTime = 50,
    [{stale_time, StaleTime} |
     start_peerbook(#{stale_time => StaleTime}, Config)];
init_per_testcase(signed_metadata_test, Config) ->
    setup(),
    Tab = ets:new(signed_metadata_test, [set, public, {write_concurrency, true}]),
    Fun = fun() ->
                  case ets:lookup(Tab, metadata_fun) of
                      [] -> #{};
                      [{_, Fun}] -> Fun()
                  end
          end,
    start_peerbook(#{metadata_fun => Fun, peer_time => 50 },
                   [{tab, Tab} | Config]);
init_per_testcase(_, Config) ->
    setup(),
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

-define(assertAsyncTimes(Tab, K,C),
        ?assertAsync(Count = case ets:lookup((Tab), (K)) of
                                 [] -> 0;
                                 [{(K), N}] -> N
                             end,
                     Count > (C))).

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
    libp2p_peerbook:register_session(Handle, PubKeyBin),
    %% And register it again to ensure it only comes listed once
    libp2p_peerbook:register_session(Handle, PubKeyBin),

    %% confirm it's stored
    ?assertAsync({ok, Peer} = libp2p_peerbook:get(Handle, PubKeyBin),
                 [PubKeyBin] == libp2p_peer:connected_peers(Peer)),

    %% unregister the session address
    libp2p_peerbook:unregister_session(Handle, PubKeyBin),
    %% Unregistering again has no effect
    libp2p_peerbook:unregister_session(Handle, PubKeyBin),
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
    ok = libp2p_peerbook:put(Handle, NewPeer),

    {ok, NewPeer} = libp2p_peerbook:get(Handle, libp2p_peer:pubkey_bin(NewPeer)),

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
    ok = libp2p_peerbook:put(Handle, NewPeer),

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
        {changed_peers, {{add, Add}, {remove, _}}} ->
            ?assert(maps:is_key(PubKeyBin, Add))
    after 1000 ->
            ct:fail(timeout_heartbeat)
    end,

    ok.

notify_test(Config) ->
    Handle = ?config(peerbook, Config),
    PubKeyBin = ?config(pubkey_bin, Config),

    %% Add two peers
    {ok, Peer1} = mk_peer(#{}),
    {ok, Peer2} = mk_peer(#{}),
    ok = libp2p_peerbook:put(Handle, Peer1),
    ok = libp2p_peerbook:put(Handle, Peer2),

    libp2p_peerbook:join_notify(Handle, self()),

    %% cause a change in the self peer
    libp2p_peerbook:set_nat_type(Handle, static),

    %% And remove one of the two peers
    Peer2PubKeyBin = libp2p_peer:pubkey_bin(Peer2),
    libp2p_peerbook:remove(Handle, Peer2PubKeyBin),

    receive
        {changed_peers, {{add, Add}, {remove, Remove}}} ->
            %% We should see the self peer and peer1 added and peer 2
            %% removed
            ?assert(lists:member(Peer2PubKeyBin, Remove)),
            ?assert(maps:is_key(PubKeyBin, Add)),
            ?assert(maps:is_key(libp2p_peer:pubkey_bin(Peer1), Add))
    after 1000 ->
            ct:fail(timeout_notify)
    end,

    libp2p_peerbook:leave_notify(Handle, self()),

    ok.

stale_test(Config) ->
    Handle = ?config(peerbook, Config),
    StaleTime = ?config(stale_time, Config),

    %% Ensure stale time is what we configured it as
    ?assertEqual(StaleTime, libp2p_peerbook:stale_time(Handle)),

    %% Add a peer
    {ok, NewPeer} = mk_peer(#{}),
    ok = libp2p_peerbook:put(Handle, NewPeer),
    ?assert(libp2p_peerbook:is_key(Handle, libp2p_peer:pubkey_bin(NewPeer))),

    %% Wait for it to get stale and no longer be gettable
    ?assertAsync(Result = libp2p_peerbook:get(Handle, libp2p_peer:pubkey_bin(NewPeer)),
                 Result == {error, not_found}),

    ok.

signed_metadata_test(Config) ->
    Handle = ?config(peerbook, Config),
    PubKeyBin = ?config(pubkey_bin, Config),
    Tab = ?config(tab, Config),
    %% Set the metdata function to a given fun
    SetMetaDataFun = fun(F) -> ets:insert(Tab, {metadata_fun, F}) end,
    %% Set the metadata function to a function that counts the number
    %% of times a given fun is executed
    SetCountedMetaDataFun = fun(K, F) ->
                                    SetMetaDataFun(fun() ->
                                                           ets:update_counter(Tab, K, 1, {K, 0}),
                                                           F()
                                                   end)
                            end,

    %% Try a normal metadata set
    SetMetaDataFun(fun() -> #{<<"hello">> => <<"world">>} end),
    ?assertAsync({ok, Peer} = libp2p_peerbook:get(Handle, PubKeyBin),
                 #{ <<"hello">> => <<"world">> } == libp2p_peer:signed_metadata(Peer)),


    %% Let the metedata crash a number of times
    SetCountedMetaDataFun(crash_count,
                          fun() -> exit(fail_metadata) end),
    ?assertAsyncTimes(Tab, crash_count, 20),
    %% Set to a slow function
    SetCountedMetaDataFun(sleep_count,
                          fun() ->
                                  timer:sleep(300),
                                  #{}
                          end),
    ?assertAsyncTimes(Tab, sleep_count, 3),

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
