%% Name used as a basename in the ets table passed in on startup
-define(PEERBOOK_SERVICE, peerbook).

%% Default peer stale time is 24 hours (in milliseconds)
-define(PEERBOOK_DEFAULT_STALE_TIME, 24 * 60 * 60 * 1000).

%% Defailt "this" peer heartbeat time 5 minutes (in milliseconds)
-define(PEERBOOK_DEFAULT_PEER_TIME, 5 * 60 * 1000).

%% Default timer for change notifications to registered
%% peers. This allows for fast arrivels to coalesce a number of
%% changed peers before a change notification is sent out
-define(PEERBOOK_DEFAULT_NOTIFY_TIME, 5 * 1000).
