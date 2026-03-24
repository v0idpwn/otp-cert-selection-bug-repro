#!/usr/bin/env escript
%%--------------------------------------------------------------------
%% Erlang TLS 1.3 client — tests cert selection with constrained
%% signature_algs.
%%
%% Usage: escript ssl_test_client.escript <host> <port>
%%--------------------------------------------------------------------
main([Host, PortStr]) ->
    Port = list_to_integer(PortStr),
    application:ensure_all_started(ssl),

    {ok, CAPem} = file:read_file("test_certs/ca.pem"),
    [{'Certificate', CACertDER, _}] = public_key:pem_decode(CAPem),

    %% RSA schemes needed in signature_algs_cert to accept the RSA CA signature
    RsaCertSchemes = [rsa_pkcs1_sha256, rsa_pss_rsae_sha256],

    run_test("RSA-only client", Host, Port, CACertDER,
             [{signature_algs, [rsa_pss_rsae_sha256]},
              {signature_algs_cert, RsaCertSchemes}]),

    run_test("ECDSA-only client", Host, Port, CACertDER,
             [{signature_algs, [ecdsa_secp256r1_sha256]},
              {signature_algs_cert, RsaCertSchemes}]);

main(_) ->
    io:format("Usage: escript ssl_test_client.escript <host> <port>~n"),
    halt(1).

run_test(Name, Host, Port, CACertDER, ExtraOpts) ->
    ClientOpts = [{verify, verify_peer},
                  {cacerts, [CACertDER]},
                  {versions, ['tlsv1.3']},
                  {server_name_indication, disable}
                  | ExtraOpts],

    case ssl:connect(Host, Port, ClientOpts, 5000) of
        {ok, Sock} ->
            io:format("  ~s: OK~n", [Name]),
            ssl:close(Sock);
        {error, Reason} ->
            io:format("  ~s: FAILED ~p~n", [Name, Reason])
    end.
