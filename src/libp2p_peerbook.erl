%% @doc A peer storage service for p2p networks
%%
%%
-module(libp2p_peerbook).

-include("libp2p_peerbook.hrl").

%% api
-export([keys/1, values/1, put/2, get/2, is_key/2, remove/2,
         peerbook_pid/1, peerbook_handle/1,
         join_notify/2, leave_notify/2,
         stale_time/1, set_nat_type/2,
         register_listen_addr/2, unregister_listen_addr/2, blacklist_listen_addr/3,
         register_session/2, unregister_session/2]).
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
-type change_remove_descriptor() :: {remove, [libp2p_crypto:pubkey_bin()]}.
-export_type([peerbook/0]).

-record(state,
        { peerbook :: peerbook(),
          nat_type = unknown :: libp2p_peer:nat_type(),
          peer_time :: pos_integer(),
          peer_timer = make_ref() :: reference(),
          notify_group :: any(),
          notify_time :: pos_integer(),
          notify_timer=undefined :: reference() | undefined,
          notify_peers={{add, #{}}, {remove, []}} :: {change_add_descriptor(), change_remove_descriptor()},
          sessions=[] :: [libp2p_crypto:pubkey_bin()],
          listen_addrs=[] :: [string()],
          metadata_fun :: fun(() -> #{binary() => binary}),
          metadata = #{} :: map(),
          metadata_ref = undefined :: undefined | reference(),
          sig_fun :: fun((binary()) -> binary())
        }).

%%
%% API
%%

%% @doc Add a peer record to the peerbook
%%
%% The peer is validated before being allowed into the peerbook. The
%% peer must:
%%
%% <ul>
%%
%% <li> Verify it's signature </li>
%% <li> Be more recent than an existing peer record for the same public key in the store </li>
%% <li> Not be stale according to the configured `stale_time' for this peerbook </li>
%% <li> Have a network_id that is compatible with the peerbook network id </li>
%% <li> Have a network_id that is compatible with the peerbook network id </li>
%%
%% </ul>
%%
%% If the peer validates it is added to the store and notified locally
%% as a changed peer. If the peer does not validate an error is
%% returned
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
                andalso peer_allowable(Handle, NewPeer) of
                true ->
                    PutValid(NewPeerId, NewPeer);
                false ->
                    {error, invalid}
            end
    end.

%% @doc Get a peer from the peerbook given a peer key in it's binary
%% form. Note that peers will expire out of the peerbook after a
%% configured `stale_time', which means a previously available peer
%% may not be available when requested again.
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

%% @doc Returns if a given peerk key is available in the store.
-spec is_key(peerbook(), libp2p_crypto:pubkey_bin()) -> boolean().
is_key(Handle=#peerbook{}, ID) ->
    case get(Handle, ID) of
        {error, _} -> false;
        {ok, _} -> true
    end.

%% @doc Gets all the keys available in the peerbook store
-spec keys(peerbook()) -> [libp2p_crypto:pubkey_bin()].
keys(Handle=#peerbook{}) ->
    fetch_keys(Handle).

%% @doc Gets all the values available in the peerbook
-spec values(peerbook()) -> [libp2p_peer:peer()].
values(Handle=#peerbook{}) ->
    fetch_peers(Handle).

%% @doc Removes the peer for a given peer key.
%%
%% Returns an error if the key is not found, or if the key is the
%% `pubkey_bin' key that the peerbook manages. If successful the
%% peerbook will notify our a chnage to any registered listeners.
-spec remove(peerbook(), libp2p_crypto:pubkey_bin()) -> ok | {error, term()}.
remove(Handle=#peerbook{pubkey_bin=ThisPeerId}, ID) ->
     case ID == ThisPeerId of
         true -> {error, no_delete};
         false ->
             case delete_peer(ID, Handle) of
                 ok ->
                     gen_server:cast(peerbook_pid(Handle), {handle_changed_peers, {remove, [ID]}});
                 {error, Error} ->
                     {error, Error}
             end
     end.

%% @doc Returns the configured `stale_time' for a peerbook
-spec stale_time(peerbook()) -> pos_integer().
stale_time(#peerbook{stale_time=StaleTime}) ->
    StaleTime.

%% @doc Join the peerbook change notification group.
%%
%% Adds the given pid to the progress group that is notified of
%% changes to the peerbook. Change notification is collected for a
%% configurable `notify_time' before it is sent out.
%%
%% When the peerbook changes a tuple is sent out with form
%% `{changed_peers, {{add, ChangeAdd}, {remove, ChangeRemove}}}',
%% where `ChangeAdd' is a map of peer keys to peers and `ChangeRemove'
%% is a list of removed peer keys.
-spec join_notify(peerbook(), pid()) -> ok.
join_notify(Handle=#peerbook{}, Joiner) ->
    gen_server:cast(peerbook_pid(Handle), {join_notify, Joiner}).

%% @doc Remove a given pid from peerbook notifications.
-spec leave_notify(peerbook(), pid()) -> ok.
leave_notify(Handle=#peerbook{}, Pid) ->
    gen_server:cast(peerbook_pid(Handle), {leave_notify, Pid}).

%% @doc Black list a given listen address for a peer.
%%
%% This is a utility method to add a given listen address (in
%% multiaddr form) to the metadata of the peer with the given peer
%% key. Blacklist metadata is used by networking code to avoid certain
%% listen addresses if they're not reachable.
%%
%% Since the blacklist is stored in the metadata for a peer it is NOT
%% gossipped over the network and it DOES expire when the peer record
%% expires.
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

%% @doc Registers a session with a remote peer with the peerbook.
%%
%% A session is represented as the public binary key of the remote
%% peer, and is maintained as part of the "self" peer record that the
%% peerbook maintains for `pubkey_bin'.
-spec register_session(peerbook(), SessionPubKeyBin::libp2p_crypto:pubkey_bin()) -> ok.
register_session(Handle=#peerbook{}, SessionPubKeyBin) ->
    gen_server:cast(peerbook_pid(Handle), {register_session, SessionPubKeyBin}).

%% @doc Removes a session from the list of sessions for the peerbook.
%%
%%  This removes the session key managed for the "self" peer managed
%%  by the peerbook.
-spec unregister_session(peerbook(), pid()) -> ok.
unregister_session(Handle=#peerbook{}, SessionPid) ->
    gen_server:cast(peerbook_pid(Handle), {unregister_session, SessionPid}).

%% @doc Registers a listen address.
%%
%% Registers a network listen address in multiaddr form for the "self"
%% record for this peerbook. A change notification is sent out for the
%% "self" record.
-spec register_listen_addr(peerbook(), ListenAddr::string()) -> ok.
register_listen_addr(Handle=#peerbook{}, ListenAddr) ->
     gen_server:cast(peerbook_pid(Handle), {register_listen_addr, ListenAddr}).

%% @doc Removes a listen address.
%%
%% Removes a network listen address in multiaddr form from the "self"
%% record for this peerbook.A change notification is sent out for the
%% "self" record.
-spec unregister_listen_addr(peerbook(), ListenAddr::string()) -> ok.
unregister_listen_addr(Handle=#peerbook{}, ListenAddr) ->
     gen_server:cast(peerbook_pid(Handle), {unregister_listen_addr, ListenAddr}).

%% @doc Sets the NAT type for the peerbook.
%%
%% The peerbook manages the `nat_type' for the "self" record
%% identified by `pubkey_bin'. Changing the nat type will updathe
%% "self" record and will send out a change notification.
-spec set_nat_type(peerbook(), libp2p_peer:nat_type()) -> ok.
set_nat_type(Handle=#peerbook{}, NatType) ->%
    gen_server:cast(peerbook_pid(Handle), {set_nat_type, NatType}).

%% @doc Get the pid for a peerbook handle.
%%
%% Most functions int he peerbook can be done through a thread safe
%% "handle". For the ones where state is involved the actual peerbook
%% pid is required. Thisutility method gets the pid for a given
%% peerbook handle.
-spec peerbook_pid(peerbook()) -> pid().
peerbook_pid(#peerbook{tid = TID}) ->
    ets:lookup_element(TID, {?PEERBOOK_SERVICE, pid}, 2).

%% @doc Get the handle for a peerbook pid.
%%
%% Most functions int he peerbook can be done through a thread safe
%% "handle". This utility method retrieves the handle, given the
%% peerbook pid.
-spec peerbook_handle(pid()) -> {ok, peerbook()} | {error, term()}.
peerbook_handle(Pid) ->
    gen_server:call(Pid, peerbook).

%%
%% gen_server
%%

start_link(Opts = #{sig_fun := _SigFun, pubkey_bin := _PubKeyBin}) ->
    MetaDataFun = maps:get(metadata_fun, Opts, fun() -> #{} end),
    NetworkID = maps:get(network_id, Opts, <<>>),
    gen_server:start_link(?MODULE,
                          Opts#{metadata_fun => MetaDataFun,
                                network_id => NetworkID
                               }, []).
%% @private
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
    ets:insert(TID, {{?PEERBOOK_SERVICE, pid}, self()}),
    %% Ensure data folder is available
    DataDir = filename:join([maps:get(data_dir, Opts, "data"), ?PEERBOOK_SERVICE]),
    ok = filelib:ensure_dir(DataDir),

    %% Create unique peer notification group
    GroupName = pg2:create([?PEERBOOK_SERVICE, make_ref()]),
    ok = pg2:create(GroupName),

    %% Fire of the associated timeout to start the notify cycle
    self() ! notify_timeout,

    StaleTime = maps:get(stale_time, Opts, ?PEERBOOK_DEFAULT_STALE_TIME),
    MkState = fun(Handle) ->
                      #state{peerbook=Handle,
                             notify_group = GroupName,
                             metadata_fun = MetaDataFun,
                             sig_fun = SigFun,
                             peer_time = maps:get(peer_time, Opts, ?PEERBOOK_DEFAULT_PEER_TIME),
                             notify_time = maps:get(notify_time, Opts, ?PEERBOOK_DEFAULT_NOTIFY_TIME)}
              end,

    case ets:lookup(TID, {?PEERBOOK_SERVICE, handle}) of
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
                    ets:insert(TID, {{?PEERBOOK_SERVICE, handle}, Handle}),
                    {ok, update_this_peer(MkState(Handle))}
            end;
        [{_, Handle}] ->
            %% we already got a handle in ETS
            {ok, update_this_peer(MkState(Handle))}
    end.

%% @private
handle_call(update_this_peer, _From, State) ->
    {reply, update_this_peer(State), State};
handle_call(peerbook, _From, State) ->
    {reply, {ok, State#state.peerbook}, State};
handle_call(Msg, _From, State) ->
    lager:warning("Unhandled call: ~p", [Msg]),
    {reply, ok, State}.

%% @private
handle_cast({handle_changed_peers, Change}, State) ->
    {noreply, handle_changed_peers(Change, State)};
handle_cast({set_nat_type, UpdatedNatType}, State=#state{}) ->
    {noreply, update_this_peer(State#state{nat_type=UpdatedNatType})};
handle_cast({unregister_session, SessionPubKeyBin}, State=#state{sessions=Sessions}) ->
    NewSessions = lists:delete(SessionPubKeyBin, Sessions),
    {noreply, update_this_peer(State#state{sessions=NewSessions})};
handle_cast({register_session, SessionPubKeyBin}, State=#state{sessions=Sessions}) ->
    case lists:member(SessionPubKeyBin, Sessions) of
        true ->
            {noreply, State};
        false ->
            NewSessions = [SessionPubKeyBin | Sessions],
            {noreply, update_this_peer(State#state{sessions=NewSessions})}
    end;
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

%% @private
handle_info({'DOWN', Ref, _, _, _}, State=#state{metadata_ref=Ref}) ->
    {noreply, State#state{metadata_ref=undefined}};
handle_info({signed_metadata, MetaData}, State=#state{}) ->
    {noreply, State#state{metadata=MetaData}};
handle_info(peer_timeout, State0=#state{}) ->
    {NewPeer, State} = mk_this_peer(State0),
    {noreply, update_this_peer(NewPeer, get_async_signed_metadata(State))};
handle_info(notify_timeout, State=#state{}) ->
    {noreply, notify_peers(State#state{notify_timer=undefined})};

handle_info(Msg, State) ->
    lager:warning("Unhandled info: ~p", [Msg]),
    {noreply, State}.

%% @private
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

-spec get_async_signed_metadata(#state{}) -> #state{}.
get_async_signed_metadata(State=#state{metadata_ref=undefined, metadata_fun=MetaDataFun}) ->
    Parent = self(),
    {_, Ref} = spawn_monitor(fun() ->
                                     Parent ! {signed_metadata, MetaDataFun()}
                             end),
    State#state{metadata_ref = Ref};
get_async_signed_metadata(State=#state{}) ->
    State.


-spec mk_this_peer(#state{}) -> {{ok, libp2p_peer:peer()} | {error, term()}, #state{}}.
mk_this_peer(State=#state{}) ->
    Result = libp2p_peer:from_map(#{ pubkey_bin => State#state.peerbook#peerbook.pubkey_bin,
                                     listen_addrs => State#state.listen_addrs,
                                     connected => State#state.sessions,
                                     nat_type => State#state.nat_type,
                                     network_id => State#state.peerbook#peerbook.network_id,
                                     signed_metadata => State#state.metadata},
                                  State#state.sig_fun),
    {Result, State}.

-spec update_this_peer(#state{}) -> #state{}.
update_this_peer(State0=#state{}) ->
    case unsafe_fetch_peer(State0#state.peerbook#peerbook.pubkey_bin, State0#state.peerbook) of
        {error, not_found} ->
            {NewPeer, State} = mk_this_peer(State0),
            update_this_peer(NewPeer, get_async_signed_metadata(State));
        {ok, _} ->
            case mk_this_peer(State0) of
                {{ok, NewPeer}, State} ->
                    update_this_peer({ok, NewPeer}, get_async_signed_metadata(State));
                {{error, Error}, State} ->
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
    %% Handle new entries and remove any "removed" entries that are now in the add map
    NewAdd = maps:merge(Add, ChangeAdd),
    NewRemove = lists:filter(fun(Entry) -> maps:is_key(Entry, NewAdd) end, Remove),
    State#state{notify_peers={{add,  NewAdd}, {remove, NewRemove}}};
handle_changed_peers({remove, ChangeRemove}, State=#state{notify_peers={{add, Add}, {remove, Remove}}}) ->
    NewAdd = maps:without(ChangeRemove, Add),
    NewRemove = lists:merge(lists:sort(ChangeRemove), Remove),
    State#state{notify_peers={{add,  NewAdd}, {remove, NewRemove}}}.

-spec notify_peers(#state{}) -> #state{}.
notify_peers(State=#state{notify_peers=Notify={{add, Add}, {remove, Remove}}, notify_group=NotifyGroup}) ->
    case maps:size(Add) > 0 orelse length(Remove) > 0 of
        true ->
            case pg2:get_members(NotifyGroup) of
                {error, _} -> ok;
                Members -> [Pid ! {changed_peers, Notify} || Pid <- Members]
            end;
        false -> ok
    end,
    erlang:send_after(State#state.notify_time, self(), notify_timeout),
    State#state{notify_peers={{add, #{}}, {remove, []}}}.


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
    case rocksdb:put(Store, Key, libp2p_peer:encode(Peer, false), []) of
        {error, Error} -> {error, Error};
        ok -> ok
    end.

-spec delete_peer(libp2p_crypto:pubkey_bin(), peerbook()) -> ok | {error, term()}.
delete_peer(ID, #peerbook{store=Store}) ->
    rocksdb:delete(Store, ID, []).
