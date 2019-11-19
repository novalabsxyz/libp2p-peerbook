-module(libp2p_peerbook).

%% api
-export([keys/1, values/1, put/2, get/2, is_key/2, remove/2,
         stale_time/1, join_notify/2, set_nat_type/2,
         register_listen_addr/2, unregister_listen_addr/2, blacklist_listen_addr/3,
         register_session/3, unregister_session/2]).
%% gen_server
-export([start_link/1, init/1, handle_call/3, handle_info/2, handle_cast/2, terminate/2]).

-behviour(gen_server).

-record(peerbook, { tid :: ets:tab(),
                    store :: rocksdb:db_handle(),
                    pubkey_bin :: libp2p_crypto:pubkey_bin(),
                    network_id :: binary(),
                    stale_time :: pos_integer()
                  }).
-type peerbook() :: #peerbook{}.

-export_type([peerbook/0]).

-record(state,
        { peerbook :: peerbook(),
          tid :: ets:tab(),
          nat_type = unknown :: libp2p_peer:nat_type(),
          peer_time :: pos_integer(),
          peer_timer = make_ref() :: reference(),
          gossip_peers_timer = make_ref() :: reference(),
          gossip_peers_timeout :: pos_integer(),
          gossip_peer_eligible_fun :: fun((libp2p_peer:peer()) -> boolean()),
          notify_group :: any(),
          notify_time :: pos_integer(),
          notify_timer=undefined :: reference() | undefined,
          notify_peers=#{} :: #{libp2p_crypto:pubkey_bin() => libp2p_peer:peer()},
          sessions=[] :: [{libp2p_crypto:pubkey_bin(), pid()}],
          listen_addrs=[] :: [string()],
          metadata_fun :: fun(() -> #{binary() => binary}),
          sig_fun :: fun((binary()) -> binary())
        }).

-define(SERVICE, peerbook).

%% Default peer stale time is 24 hours (in milliseconds)
-define(DEFAULT_STALE_TIME, 24 * 60 * 60 * 1000).
%% Defailt "this" peer heartbeat time 5 minutes (in milliseconds)
-define(DEFAULT_PEER_TIME, 5 * 60 * 1000).
%% Default timer for new peer notifications to connected peers. This
%% allows for fast arrivels to coalesce a number of new peers before a
%% new list is sent out.
-define(DEFAULT_NOTIFY_TIME, 5 * 1000).
%% number of recently updated peerbook entries we should regossip to our
%% gossip peers
-define(DEFAULT_NOTIFY_PEER_GOSSIP_LIMIT, 5).
%% Default timeout for selecting eligible gossip peers. Set to 30
%% minutes (in milliseconds)
-define(DEFAULT_GOSSIP_PEERS_TIMEOUT, 30 * 60 * 1000).

%%
%% API
%%

-spec put(peerbook(), [libp2p_peer:peer()]) -> ok | {error, term()}.
put(#peerbook{stale_time=StaleTime, pubkey_bin=ThisPeerId, network_id=NetworkID}=Handle, PeerList) ->
    NewPeers = lists:filter(fun(NewPeer) ->
                                    NewPeerId = libp2p_peer:pubkey_bin(NewPeer),
                                    case unsafe_fetch_peer(NewPeerId, Handle) of
                                        {error, not_found} -> true;
                                        {ok, ExistingPeer} ->
                                            %% Only store peers that meet some key criteria
                                            NewPeerId /= ThisPeerId
                                                andalso libp2p_peer:verify(NewPeer)
                                                andalso libp2p_peer:supersedes(NewPeer, ExistingPeer)
                                                andalso not libp2p_peer:is_stale(NewPeer, StaleTime)
                                                andalso not libp2p_peer:is_similar(NewPeer, ExistingPeer)
                                                andalso libp2p_peer:network_id_allowable(NewPeer, NetworkID)
                                    end
                            end, PeerList),

    % Add new peers to the store
    lists:foreach(fun(P) -> store_peer(P, Handle) end, NewPeers),
    % Notify group of new peers
    gen_server:cast(peerbook_pid(Handle), {notify_new_peers, NewPeers}),
    ok.

-spec get(peerbook(), libp2p_crypto:pubkey_bin()) -> {ok, libp2p_peer:peer()} | {error, term()}.
get(#peerbook{pubkey_bin=ThisPeerId}=Handle, ID) ->
    case fetch_peer(ID, Handle) of
        {error, not_found} when ID == ThisPeerId ->
            gen_server:call(peerbook_pid(Handle), update_this_peer, infinity),
            get(Handle, ID);
        {error, Error} ->
            {error, Error};
        {ok, Peer} ->
            case libp2p_peer:network_id_allowable(Peer, Handle#peerbook.network_id) of
               false ->
                    {error, not_found};
                true ->
                    {ok, Peer}
            end
    end.

-spec is_key(peerbook(), libp2p_crypto:pubkey_bin()) -> boolean().
is_key(Handle=#peerbook{}, ID) ->
    case get(Handle, ID) of
        {error, _} -> false;
        {ok, _} -> true
    end.

-spec keys(peerbook()) -> [libp2p_crypto:pubkey_bin()].
keys(Handle=#peerbook{}) ->
    fetch_keys(Handle).

-spec values(peerbook()) -> [libp2p_peer:peer()].
values(Handle=#peerbook{}) ->
    fetch_peers(Handle).

-spec remove(peerbook(), libp2p_crypto:pubkey_bin()) -> ok | {error, no_delete}.
remove(Handle=#peerbook{pubkey_bin=ThisPeerId}, ID) ->
     case ID == ThisPeerId of
         true -> {error, no_delete};
         false -> delete_peer(ID, Handle)
     end.

-spec stale_time(peerbook()) -> pos_integer().
stale_time(#peerbook{stale_time=StaleTime}) ->
    StaleTime.

-spec blacklist_listen_addr(peerbook(), libp2p_crypto:pubkey_bin(), ListenAddr::string())
                           -> ok | {error, not_found}.
blacklist_listen_addr(Handle=#peerbook{}, ID, ListenAddr) ->
    case unsafe_fetch_peer(ID, Handle) of
        {error, Error} ->
            {error, Error};
        {ok, Peer} ->
            UpdatedPeer = libp2p_peer:blacklist_add(Peer, ListenAddr),
            store_peer(UpdatedPeer, Handle)
    end.

-spec join_notify(peerbook(), pid()) -> ok.
join_notify(Handle=#peerbook{}, Joiner) ->
    gen_server:cast(peerbook_pid(Handle), {join_notify, Joiner}).

-spec register_session(peerbook(), libp2p_crypto:pubkey_bin(), pid()) -> ok.
register_session(Handle=#peerbook{}, SessionAddr, SessionPid) ->
    gen_server:cast(peerbook_pid(Handle), {register_session, {SessionAddr, SessionPid}}).

-spec unregister_session(peerbook(), pid()) -> ok.
unregister_session(Handle=#peerbook{}, SessionPid) ->
    gen_server:cast(peerbook_pid(Handle), {unregister_session, SessionPid}).

-spec register_listen_addr(peerbook(), ListenAddr::string()) -> ok.
register_listen_addr(Handle=#peerbook{}, ListenAddr) ->
     gen_server:cast(peerbook_pid(Handle), {register_listen_addr, ListenAddr}).

-spec unregister_listen_addr(peerbook(), ListenAddr::string()) -> ok.
unregister_listen_addr(Handle=#peerbook{}, ListenAddr) ->
     gen_server:cast(peerbook_pid(Handle), {unregister_listen_addr, ListenAddr}).

-spec set_nat_type(peerbook(), libp2p_peer:nat_type()) -> ok.
set_nat_type(Handle=#peerbook{}, NatType) ->%
    gen_server:cast(peerbook_pid(Handle), {set_nat_type, NatType}).

-spec peerbook_pid(#peerbook{}) -> pid().
peerbook_pid(#peerbook{tid = TID}) ->
    ets:lookup_element(TID, {?SERVICE, pid}, 2).
%%
%% gen_server
%%

start_link(Opts = #{sig_fun := _SigFun, pubkey_bin := _PubKeyBin, network_id := _NetworkID}) ->
    TID = case maps:get(tid, Opts, false) of
              false ->
                  ets:new(?MODULE, [public, ordered_set, {read_concurrency, true}]);
              Table -> Table
          end,
    MetaDataFun = maps:get(metadata_fun, Opts, fun() -> #{} end),
    EligibleFun = maps:get(peer_gossip_eligible_fun, Opts, fun(_Peer) -> true end),
    gen_server:start_link(?MODULE, Opts#{tid => TID,
                                         metadata_fun => MetaDataFun,
                                         peer_gossip_eligible_fun => EligibleFun}, []).

init(Opts = #{ sig_fun := SigFun,
               tid := TID,
               metadata_fun := MetaDataFun,
               peer_gossip_eligible_fun := EligibleFun,
               network_id := NetworkID,
               pubkey_bin := PubKeyBin }) ->
    erlang:process_flag(trap_exit, true),
    ets:insert(TID, {{?SERVICE, pid}, self()}),
    %% Ensure data folder is available
    DataDir = filename:join([maps:get(data_dir, Opts, "data"), ?SERVICE]),
    ok = filelib:ensure_dir(DataDir),

    %% Create unique peer notification group
    GroupName = pg2:create([?SERVICE, make_ref()]),
    ok = pg2:create(GroupName),

    %% initialize elligible gossip peer cache
    ets:insert(TID, {{?SERVICE, eligible_gossip_peers}, []}),
    %% Fire of the associated timeout to refresh the eligible gossip cache
    self() ! gossip_peers_timeout,

    StaleTime = maps:get(stale_time, Opts, ?DEFAULT_STALE_TIME),
    MkState = fun(Handle) ->
                      #state{tid=TID,
                             peerbook=Handle,
                             notify_group = GroupName,
                             metadata_fun = MetaDataFun,
                             sig_fun = SigFun,
                             peer_time = maps:get(peer_time, Opts, ?DEFAULT_PEER_TIME),
                             notify_time = maps:get(notify_time, Opts, ?DEFAULT_NOTIFY_TIME),
                             gossip_peer_eligible_fun = EligibleFun,
                             gossip_peers_timeout = maps:get(gossip_peers_timeout, Opts,
                                                             ?DEFAULT_GOSSIP_PEERS_TIMEOUT)}
              end,

    case ets:lookup(TID, {?SERVICE, handle}) of
        [] ->
            DBOpts = application:get_env(rocksdb, global_opts, []),
            %% Do a repar just in case DB gets corrupted
            ok = rocksdb:repair(DataDir, []),
            case rocksdb:open_with_ttl(DataDir,
                                       [{create_if_missing, true} | DBOpts],
                                       (2 * StaleTime) div 1000, false) of
                {error, Reason} ->
                    {stop, Reason};
                {ok, DB} ->
                    Handle = #peerbook{store = DB,
                                       tid = TID,
                                       pubkey_bin = PubKeyBin,
                                       network_id = NetworkID,
                                       stale_time = StaleTime},
                    ets:insert(TID, {{?SERVICE, handle}, Handle}),
                    {ok, update_this_peer(MkState(Handle))}
            end;
        [{_, Handle}] ->
            %% we already got a handle in ETS
            {ok, update_this_peer(MkState(Handle))}
    end.

handle_call(update_this_peer, _From, State) ->
    {reply, update_this_peer(State), State};
handle_call(Msg, _From, State) ->
    lager:warning("Unhandled call: ~p", [Msg]),
    {reply, ok, State}.

handle_cast({notify_new_peers, Peers}, State) ->
    {noreply, notify_new_peers(Peers, State)};
handle_cast(changed_listener, State=#state{}) ->
    {noreply, update_this_peer(State)};
handle_cast({set_nat_type, UpdatedNatType}, State=#state{}) ->
    {noreply, update_this_peer(State#state{nat_type=UpdatedNatType})};
handle_cast({unregister_session, SessionPid}, State=#state{sessions=Sessions}) ->
    NewSessions = lists:filter(fun({_Addr, Pid}) -> Pid /= SessionPid end, Sessions),
    {noreply, update_this_peer(State#state{sessions=NewSessions})};
handle_cast({register_session, {SessionAddr, SessionPid}},
            State=#state{sessions=Sessions}) ->
    NewSessions = [{SessionAddr, SessionPid} | Sessions],
    {noreply, update_this_peer(State#state{sessions=NewSessions})};
handle_cast({join_notify, JoinPid}, State=#state{notify_group=Group}) ->
    %% only allow a pid to join once
    case lists:member(JoinPid, pg2:get_members(Group)) of
        false ->
            ok = pg2:join(Group, JoinPid);
        true ->
            ok
    end,
    {noreply, State};
handle_cast(Msg, State) ->
    lager:warning("Unhandled cast: ~p", [Msg]),
    {noreply, State}.

handle_info(peer_timeout, State=#state{}) ->
    {noreply, update_this_peer(mk_this_peer(State), State)};
handle_info(notify_timeout, State=#state{}) ->
    {noreply, notify_peers(State#state{notify_timer=undefined})};
handle_info(gossip_peers_timeout, State=#state{gossip_peer_eligible_fun=EligibleFun}) ->
    %% TODO longer term use peer updates to update the elegible peers
    %% list and avoid folding the peerbook at all
    EligiblePeerKeys = fold_peers(fun(_, Peer, Acc) ->
                                          case EligibleFun(Peer) of
                                              true -> [libp2p_peer:pubkey_bin(Peer) | Acc];
                                              false -> Acc
                                       end
                               end, [], State#state.peerbook),
    ets:insert(State#state.tid, {{?SERVICE, eligible_gossip_peers}, EligiblePeerKeys}),
    NewTimer = erlang:send_after(State#state.gossip_peers_timeout, self(), gossip_peers_timeout),
    {noreply, State#state{gossip_peers_timer=NewTimer}};

handle_info(Msg, State) ->
    lager:warning("Unhandled info: ~p", [Msg]),
    {noreply, State}.

terminate(shutdown, State=#state{peerbook=#peerbook{store=Store}}) ->
    %% only close the db on shutdown
    rocksdb:close(Store),
    pg2:delete(State#state.notify_group);
terminate(_Reason, State) ->
    pg2:delete(State#state.notify_group).


%%
%% Internal
%%

-spec mk_this_peer(#state{}) -> {ok, libp2p_peer:peer()} | {error, term()}.
mk_this_peer(State=#state{}) ->
    ConnectedAddrs = sets:to_list(sets:from_list([Addr || {Addr, _} <- State#state.sessions])),
    %% if the metadata fun crashes, simply return an empty map
    MetaData = try (State#state.metadata_fun)() of
                   Result ->
                       Result
               catch
                   _:_ -> #{}
               end,
    libp2p_peer:from_map(#{ pubkey => State#state.peerbook#peerbook.pubkey_bin,
                            listen_addrs => State#state.listen_addrs,
                            connected => ConnectedAddrs,
                            nat_type => State#state.nat_type,
                            network_id => State#state.peerbook#peerbook.network_id,
                            signed_metadata => MetaData},
                         State#state.sig_fun).

-spec update_this_peer(#state{}) -> #state{}.
update_this_peer(State=#state{}) ->
    case unsafe_fetch_peer(State#state.peerbook#peerbook.pubkey_bin, State#state.peerbook) of
        {error, not_found} ->
            NewPeer = mk_this_peer(State),
            update_this_peer(NewPeer, State);
        {ok, OldPeer} ->
            case mk_this_peer(State) of
                {ok, NewPeer} ->
                    case libp2p_peer:is_similar(NewPeer, OldPeer) of
                        true -> State;
                        false -> update_this_peer({ok, NewPeer}, State)
                    end;
                {error, Error} ->
                    lager:notice("Failed to make peer: ~p", [Error]),
                    State
            end
    end.

-spec update_this_peer({ok, libp2p_peer:peer()} | {error, term()}, #state{}) -> #state{}.
update_this_peer({error, _Error}, State=#state{peer_timer=PeerTimer}) ->
    erlang:cancel_timer(PeerTimer),
    NewPeerTimer = erlang:send_after(State#state.peer_time, self(), peer_timeout),
    State#state{peer_timer=NewPeerTimer};
update_this_peer({ok, NewPeer}, State=#state{peer_timer=PeerTimer}) ->
    store_peer(NewPeer, State#state.peerbook),
    erlang:cancel_timer(PeerTimer),
    NewPeerTimer = erlang:send_after(State#state.peer_time, self(), peer_timeout),
    notify_new_peers([NewPeer], State#state{peer_timer=NewPeerTimer}).

-spec notify_new_peers([libp2p_peer:peer()], #state{}) -> #state{}.
notify_new_peers([], State=#state{}) ->
    State;
notify_new_peers(NewPeers, State=#state{notify_timer=NotifyTimer, notify_time=NotifyTime,
                                        notify_peers=NotifyPeers}) ->
    %% Cache the new peers to be sent out but make sure that the new
    %% peers are not stale.  We do that by only replacing already
    %% cached versions if the new peers supersede existing ones
    NewNotifyPeers = lists:foldl(
                       fun (Peer, Acc) ->
                               case maps:find(libp2p_peer:pubkey_bin(Peer), Acc) of
                                   error -> maps:put(libp2p_peer:pubkey_bin(Peer), Peer, Acc);
                                   {ok, FoundPeer} ->
                                       case libp2p_peer:supersedes(Peer, FoundPeer) of
                                           true -> maps:put(libp2p_peer:pubkey_bin(Peer), Peer, Acc);
                                           false -> Acc
                                       end
                               end
                       end, NotifyPeers, NewPeers),
    %% Set up a timer if ntot already set. This ensures that fast new
    %% peers will keep notifications ticking at the notify_time, but
    %% that no timer is firing if there's nothing to notify.
    NewNotifyTimer = case NotifyTimer of
                         undefined when map_size(NewNotifyPeers) > 0 ->
                             erlang:send_after(NotifyTime, self(), notify_timeout);
                         Other -> Other
                     end,
    State#state{notify_peers=NewNotifyPeers, notify_timer=NewNotifyTimer}.

-spec notify_peers(#state{}) -> #state{}.
notify_peers(State=#state{notify_peers=NotifyPeers}) when map_size(NotifyPeers) == 0 ->
    State;
notify_peers(State=#state{notify_peers=NotifyPeers, notify_group=NotifyGroup}) ->
    %% Notify to local interested parties
    PeerList = maps:values(NotifyPeers),
    [Pid ! {new_peers, PeerList} || Pid <- pg2:get_members(NotifyGroup)],
    State#state{notify_peers=#{}}.


%% rocksdb has a bad spec that doesn't list corruption as a valid return
%% so this is here until that gets fixed
-dialyzer({nowarn_function, unsafe_fetch_peer/2}).
-spec unsafe_fetch_peer(libp2p_crypto:pubkey_bin() | undefined, peerbook())
                       -> {ok, libp2p_peer:peer()} | {error, not_found}.
unsafe_fetch_peer(undefined, _) ->
    {error, not_found};
unsafe_fetch_peer(ID, #peerbook{store=Store}) ->
    case rocksdb:get(Store, ID, []) of
        {ok, Bin} -> libp2p_peer:decode(Bin);
        %% we can get 'corruption' when the system time is not at least 05/09/2013:5:40PM GMT-8
        %% https://github.com/facebook/rocksdb/blob/4decff6fa8c4d46e905a66d439394c4bfb889a69/utilities/ttl/db_ttl_impl.cc#L154
        corruption -> {error, not_found};
        {error, {corruption, _}} -> {error, not_found};
        not_found -> {error, not_found}
    end.

-spec fetch_peer(libp2p_crypto:pubkey_bin(), peerbook())
                -> {ok, libp2p_peer:peer()} | {error, term()}.
fetch_peer(ID, Handle=#peerbook{stale_time=StaleTime}) ->
    case unsafe_fetch_peer(ID, Handle) of
        {ok, Peer} ->
            case libp2p_peer:is_stale(Peer, StaleTime) of
                true -> {error, not_found};
                false -> {ok, Peer}
            end;
        {error, Error} -> {error,Error}
    end.


fold_peers(Fun, Acc0, #peerbook{network_id=NetworkID, store=Store, stale_time=StaleTime}) ->
    {ok, Iterator} = rocksdb:iterator(Store, []),
    fold(Iterator, rocksdb:iterator_move(Iterator, first),
         fun(Key, Bin, Acc) ->
                 {ok, Peer} = libp2p_peer:decode(Bin),
                 case libp2p_peer:is_stale(Peer, StaleTime)
                     orelse not libp2p_peer:network_id_allowable(Peer, NetworkID) of
                     true -> Acc;
                     false -> Fun(Key, Peer, Acc)
                 end
         end, Acc0).

fold(Iterator, {error, _}, _Fun, Acc) ->
    rocksdb:iterator_close(Iterator),
    Acc;
fold(Iterator, {ok, Key, Value}, Fun, Acc) ->
    fold(Iterator, rocksdb:iterator_move(Iterator, next), Fun, Fun(Key, Value, Acc)).

-spec fetch_keys(peerbook()) -> [libp2p_crypto:pubkey_bin()].
fetch_keys(State=#peerbook{}) ->
    fold_peers(fun(Key, _, Acc) -> [Key | Acc] end, [], State).

-spec fetch_peers(peerbook()) -> [libp2p_peer:peer()].
fetch_peers(State=#peerbook{}) ->
    fold_peers(fun(_, Peer, Acc) -> [Peer | Acc] end, [], State).

-spec store_peer(libp2p_peer:peer(), peerbook()) -> ok | {error, term()}.
store_peer(Peer, #peerbook{store=Store}) ->
    case rocksdb:put(Store, libp2p_peer:pubkey_bin(Peer), libp2p_peer:encode(Peer), []) of
        {error, Error} -> {error, Error};
        ok -> ok
    end.

-spec delete_peer(libp2p_crypto:pubkey_bin(), peerbook()) -> ok.
delete_peer(ID, #peerbook{store=Store}) ->
    rocksdb:delete(Store, ID, []).
