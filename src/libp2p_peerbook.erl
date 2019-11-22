-module(libp2p_peerbook).

%% api
-export([keys/1, values/1, put/2, get/2, is_key/2, remove/2,
         peerbook_pid/1, peerbook_handle/1,
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

-type change_descriptor() :: change_add_descriptor() | change_remove_descriptor().
-type change_add_descriptor() :: {add, #{libp2p_crypto:pubkey_bin() => libp2p_peer:peer()}}.
-type change_remove_descriptor() :: {remove, sets:set(libp2p_crypto:pubkey_bin())}.
-export_type([peerbook/0]).

-record(state,
        { peerbook :: peerbook(),
          nat_type = unknown :: libp2p_peer:nat_type(),
          peer_time :: pos_integer(),
          peer_timer = make_ref() :: reference(),
          notify_group :: any(),
          notify_time :: pos_integer(),
          notify_timer=undefined :: reference() | undefined,
          notify_peers={{add, #{}},
                        {remove, sets:new()}} :: {change_add_descriptor(), change_remove_descriptor()},
          sessions=[] :: [{libp2p_crypto:pubkey_bin(), pid()}],
          listen_addrs=[] :: [string()],
          metadata_fun :: fun(() -> #{binary() => binary}),
          sig_fun :: fun((binary()) -> binary())
        }).

%% Name used as a basename in ets table
-define(SERVICE, peerbook).

%% Default peer stale time is 24 hours (in milliseconds)
-define(DEFAULT_STALE_TIME, 24 * 60 * 60 * 1000).
%% Defailt "this" peer heartbeat time 5 minutes (in milliseconds)
-define(DEFAULT_PEER_TIME, 5 * 60 * 1000).
%% Default timer for new peer notifications to connected peers. This
%% allows for fast arrivels to coalesce a number of new peers before a
%% new list is sent out.
-define(DEFAULT_NOTIFY_TIME, 5 * 1000).


%%
%% API
%%

-spec put(peerbook(), libp2p_peer:peer()) -> ok | {error, term()}.
put(Handle=#peerbook{pubkey_bin=ThisPeerId}, NewPeer) ->
    PutValid = fun(PeerId, Peer) ->
                       store_peer(PeerId, Peer, Handle),
                       %% Notify group of new peers
                       gen_server:cast(peerbook_pid(Handle), {handle_changed_peers,
                                                              {add, #{PeerId => NewPeer}}})
               end,
    NewPeerId = libp2p_peer:pubkey_bin(NewPeer),
    case unsafe_fetch_peer(NewPeerId, Handle) of
        {error, not_found} ->
            PutValid(NewPeerId, NewPeer);
        {ok, ExistingPeer} ->
            case
                %% Only store peers that meet some key criteria
                NewPeerId /= ThisPeerId
                andalso libp2p_peer:verify(NewPeer)
                andalso libp2p_peer:supersedes(NewPeer, ExistingPeer)
                andalso not libp2p_peer:is_similar(NewPeer, ExistingPeer)
                andalso peer_allowable(Handle, NewPeer) of
                true ->
                    PutValid(NewPeerId, NewPeer);
                false ->
                    {error, not_allowed}
            end
    end.

-spec get(peerbook(), libp2p_crypto:pubkey_bin()) -> {ok, libp2p_peer:peer()} | {error, term()}.
get(#peerbook{pubkey_bin=ThisPeerId}=Handle, ID) ->
    case unsafe_fetch_peer(ID, Handle) of
        {error, not_found} when ID == ThisPeerId ->
            gen_server:call(peerbook_pid(Handle), update_this_peer, infinity),
            get(Handle, ID);
        {error, Error} ->
            {error, Error};
        {ok, Peer} ->
            case peer_allowable(Handle, Peer) of
                true -> {ok, Peer};
               false -> {error, not_found}
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

-spec remove(peerbook(), libp2p_crypto:pubkey_bin()) -> ok | {error, term()}.
remove(Handle=#peerbook{pubkey_bin=ThisPeerId}, ID) ->
     case ID == ThisPeerId of
         true -> {error, no_delete};
         false ->
             case delete_peer(ID, Handle) of
                 ok ->
                     gen_server:cast(peerbook_pid(Handle), {handle_changed_peers,
                                                            {remove, sets:from_list([ID])}});
                 {error, Error} ->
                     {error, Error}
             end
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
            {ok, UpdatedPeer} = libp2p_peer:blacklist_add(Peer, ListenAddr),
            store_peer(ID, UpdatedPeer, Handle)
    end.

-spec join_notify(peerbook(), pid()) -> ok.
join_notify(Handle=#peerbook{}, Joiner) ->
    gen_server:cast(peerbook_pid(Handle), {join_notify, Joiner}).

-spec register_session(peerbook(), libp2p_crypto:pubkey_bin(), pid()) -> ok.
register_session(Handle=#peerbook{}, SessionPubKeyBin, SessionPid) ->
    gen_server:cast(peerbook_pid(Handle), {register_session, {SessionPubKeyBin, SessionPid}}).

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

-spec peerbook_pid(peerbook()) -> pid().
peerbook_pid(#peerbook{tid = TID}) ->
    ets:lookup_element(TID, {?SERVICE, pid}, 2).

-spec peerbook_handle(pid()) -> {ok, peerbook()} | {error, term()}.
peerbook_handle(Pid) ->
    gen_server:call(Pid, peerbook).

%%
%% gen_server
%%

start_link(Opts = #{sig_fun := _SigFun, pubkey_bin := _PubKeyBin}) ->
    MetaDataFun = maps:get(metadata_fun, Opts, fun() -> #{} end),
    NetworkID = maps:get(netowrk_id, Opts, <<>>),
    gen_server:start_link(?MODULE,
                          Opts#{metadata_fun => MetaDataFun,
                                network_id => NetworkID
                               }, []).

init(Opts = #{ sig_fun := SigFun,
               metadata_fun := MetaDataFun,
               network_id := NetworkID,
               pubkey_bin := PubKeyBin }) ->
    erlang:process_flag(trap_exit, true),
    TID = case maps:get(tid, Opts, false) of
              false ->
                  ets:new(?MODULE, [ordered_set, {read_concurrency, true}]);
              Table -> Table
          end,
    ets:insert(TID, {{?SERVICE, pid}, self()}),
    %% Ensure data folder is available
    DataDir = filename:join([maps:get(data_dir, Opts, "data"), ?SERVICE]),
    ok = filelib:ensure_dir(DataDir),

    %% Create unique peer notification group
    GroupName = pg2:create([?SERVICE, make_ref()]),
    ok = pg2:create(GroupName),

    %% Fire of the associated timeout to start the notify cycle
    self() ! notify_timeout,

    StaleTime = maps:get(stale_time, Opts, ?DEFAULT_STALE_TIME),
    MkState = fun(Handle) ->
                      #state{peerbook=Handle,
                             notify_group = GroupName,
                             metadata_fun = MetaDataFun,
                             sig_fun = SigFun,
                             peer_time = maps:get(peer_time, Opts, ?DEFAULT_PEER_TIME),
                             notify_time = maps:get(notify_time, Opts, ?DEFAULT_NOTIFY_TIME)}
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
handle_call(peerbook, _From, State) ->
    {reply, {ok, State#state.peerbook}, State};
handle_call(Msg, _From, State) ->
    lager:warning("Unhandled call: ~p", [Msg]),
    {reply, ok, State}.

handle_cast({handle_changed_peers, Change}, State) ->
    {noreply, handle_changed_peers(Change, State)};
handle_cast({set_nat_type, UpdatedNatType}, State=#state{}) ->
    {noreply, update_this_peer(State#state{nat_type=UpdatedNatType})};
handle_cast({unregister_session, SessionPid}, State=#state{sessions=Sessions}) ->
    NewSessions = lists:filter(fun({_Addr, Pid}) -> Pid /= SessionPid end, Sessions),
    {noreply, update_this_peer(State#state{sessions=NewSessions})};
handle_cast({register_session, {SessionPubKeyBin, SessionPid}},
            State=#state{sessions=Sessions}) ->
    NewSessions = [{SessionPubKeyBin, SessionPid} | Sessions],
    {noreply, update_this_peer(State#state{sessions=NewSessions})};
handle_cast({unregister_listen_addr, ListenAddr}, State=#state{}) ->
    ListenAddrs = lists:filter(fun(Addr) -> Addr /= ListenAddr end, State#state.listen_addrs),
    {noreply, update_this_peer(State#state{listen_addrs=ListenAddrs})};
handle_cast({register_listen_addr, ListenAddr}, State=#state{}) ->
    ListenAddrs = [ListenAddr | State#state.listen_addrs],
    {noreply, update_this_peer(State#state{listen_addrs=ListenAddrs})};
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


-spec peer_allowable(peerbook(), libp2p_peer:peer()) -> boolean().
peer_allowable(Handle=#peerbook{}, Peer) ->
    not libp2p_peer:is_stale(Peer, Handle#peerbook.stale_time) andalso
        libp2p_peer:network_id_allowable(Peer, Handle#peerbook.network_id).


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
    libp2p_peer:from_map(#{ pubkey_bin => State#state.peerbook#peerbook.pubkey_bin,
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
update_this_peer(Result, State=#state{peer_timer=PeerTimer}) ->
    erlang:cancel_timer(PeerTimer),
    NewPeerTimer = erlang:send_after(State#state.peer_time, self(), peer_timeout),
    NewState = State#state{peer_timer=NewPeerTimer},
    case Result of
        {error, _Error} -> NewState;
        {ok, NewPeer} ->
            store_peer(libp2p_peer:pubkey_bin(NewPeer), NewPeer, State#state.peerbook),
            handle_changed_peers({add, #{libp2p_peer:pubkey_bin(NewPeer) => NewPeer}}, NewState)
    end.

-spec handle_changed_peers(change_descriptor(), #state{}) -> #state{}.
handle_changed_peers({add, ChangeAdd}, State=#state{notify_peers={{add, Add}, {remove, Remove}}}) ->
    %% Handle new entries and remove any "removed" entries
    NewAdd = maps:merge(Add, ChangeAdd),
    NewRemove = sets:subtract(Remove, sets:from_list(maps:keys(ChangeAdd))),
    State#state{notify_peers={{add,  NewAdd}, {remove, NewRemove}}};
handle_changed_peers({remove, ChangeRemove}, State=#state{notify_peers={{add, Add}, {remove, Remove}}}) ->
    NewAdd = maps:without(sets:to_list(ChangeRemove), Add),
    NewRemove = sets:union(ChangeRemove, Remove),
    State#state{notify_peers={{add,  NewAdd}, {remove, NewRemove}}}.

-spec notify_peers(#state{}) -> #state{}.
notify_peers(State=#state{notify_peers=Notify={{add, Add}, {remove, Remove}}, notify_group=NotifyGroup}) ->
    case maps:size(Add) > 0 orelse sets:size(Remove) > 0 of
        true ->
            [Pid ! {changed_peers, Notify} || Pid <- pg2:get_members(NotifyGroup)];
        false -> ok
    end,
    erlang:send_after(State#state.notify_time, self(), notify_timeout),
    State#state{notify_peers={{add, #{}}, {remove, sets:new()}}}.


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


fold_peers(Fun, Acc0, Handle=#peerbook{}) ->
    {ok, Iterator} = rocksdb:iterator(Handle#peerbook.store, []),
    fold(Iterator, rocksdb:iterator_move(Iterator, first),
         fun(Key, Bin, Acc) ->
                 {ok, Peer} = libp2p_peer:decode(Bin),
                 case peer_allowable(Handle, Peer) of
                     false -> Acc;
                     true -> Fun(Key, Peer, Acc)
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

-spec store_peer(libp2p_crypto:pubkey_bin(), libp2p_peer:peer(), peerbook()) -> ok | {error, term()}.
store_peer(Key, Peer, #peerbook{store=Store}) ->
    case rocksdb:put(Store, Key, libp2p_peer:encode(Peer), []) of
        {error, Error} -> {error, Error};
        ok -> ok
    end.

-spec delete_peer(libp2p_crypto:pubkey_bin(), peerbook()) -> ok | {error, term()}.
delete_peer(ID, #peerbook{store=Store}) ->
    rocksdb:delete(Store, ID, []).
