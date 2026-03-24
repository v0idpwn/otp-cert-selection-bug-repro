#!/usr/bin/env escript
%%--------------------------------------------------------------------
%% Erlang TLS 1.3 server with ECDSA + RSA certs (both signed by RSA CA).
%%
%% Listens on a port and accepts connections until killed.
%%
%% Usage: escript ssl_erlang_server.escript <port>
%%--------------------------------------------------------------------
main(Args) ->
    application:ensure_all_started(ssl),

    [PortStr] = Args,
    RequestedPort = list_to_integer(PortStr),

    %% Load certs from the Erlang term file written by ssl_gen_test_certs.escript
    {ok, [Terms]} = file:consult("test_certs/server.erlang"),
    #{ca_cert := CACertDER,
      ecdsa_server := ECDSAServerDER,
      rsa_server := RSAServerDER} = Terms,

    GetCertKey = fun(Opts) ->
                         #{cert => proplists:get_value(cert, Opts),
                           key  => proplists:get_value(key, Opts)}
                 end,

    CertsKeys = [GetCertKey(ECDSAServerDER), GetCertKey(RSAServerDER)],

    ServerOpts = [{certs_keys, CertsKeys},
                  {cacerts, [CACertDER]},
                  {versions, ['tlsv1.3']},
                  {reuseaddr, true}],

    {ok, LSock} = ssl:listen(RequestedPort, ServerOpts),
    io:format("Erlang SSL server listening on port ~p~n", [RequestedPort]),

    accept_loop(LSock).

accept_loop(LSock) ->
    {ok, ASock} = ssl:transport_accept(LSock),
    case ssl:handshake(ASock, 5000) of
        {ok, SSock} ->
            ssl:close(SSock);
        {error, Reason} ->
            io:format("Handshake error: ~p~n", [Reason])
    end,
    accept_loop(LSock).
