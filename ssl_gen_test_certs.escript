#!/usr/bin/env escript
%%--------------------------------------------------------------------
%% Generates test certificates (PEM files) for the cert selection experiment.
%%
%% Creates:
%%   test_certs/ca.pem          - RSA CA certificate
%%   test_certs/ecdsa_cert.pem  - ECDSA leaf cert (signed by RSA CA)
%%   test_certs/ecdsa_key.pem   - ECDSA leaf private key
%%   test_certs/rsa_cert.pem    - RSA leaf cert (signed by RSA CA)
%%   test_certs/rsa_key.pem     - RSA leaf private key
%%   test_certs/server.erlang   - Erlang term file with DER configs
%%
%% Run: escript ssl_gen_test_certs.escript
%%--------------------------------------------------------------------
main(_) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),

    Dir = "test_certs",
    ok = filelib:ensure_dir(filename:join(Dir, "dummy")),

    %% 1. RSA root CA
    RsaRootKey = public_key:generate_key({rsa, 2048, 65537}),
    RsaRoot = public_key:pkix_test_root_cert("RSA Test CA",
                                              [{key, RsaRootKey},
                                               {digest, sha256}]),
    #{cert := RsaCACertDER} = RsaRoot,

    %% 2. ECDSA leaf (signed by RSA CA)
    ECDSAConf = public_key:pkix_test_data(
                  #{server_chain =>
                        #{root => RsaRoot,
                          intermediates => [],
                          peer => [{key, {namedCurve, secp256r1}},
                                   {digest, sha256}]},
                    client_chain =>
                        #{root => RsaRoot,
                          intermediates => [],
                          peer => [{key, {namedCurve, secp256r1}},
                                   {digest, sha256}]}}),
    #{server_config := ECDSAServerDER} = ECDSAConf,

    %% 3. RSA leaf (signed by RSA CA)
    RSAConf = public_key:pkix_test_data(
                #{server_chain =>
                      #{root => RsaRoot,
                        intermediates => [],
                        peer => [{key, {rsa, 2048, 65537}},
                                 {digest, sha256}]},
                  client_chain =>
                      #{root => RsaRoot,
                        intermediates => [],
                        peer => [{key, {rsa, 2048, 65537}},
                                 {digest, sha256}]}}),
    #{server_config := RSAServerDER} = RSAConf,

    %% Write CA cert PEM
    CAPem = public_key:pem_encode(
              [{'Certificate', RsaCACertDER, not_encrypted}]),
    ok = file:write_file(filename:join(Dir, "ca.pem"), CAPem),

    %% Write leaf certs and keys as PEM
    write_cert_key(Dir, "ecdsa", ECDSAServerDER, RsaCACertDER),
    write_cert_key(Dir, "rsa", RSAServerDER, RsaCACertDER),

    %% Write Erlang terms for the Erlang server to consume
    ErlangTerms = #{ca_cert => RsaCACertDER,
                    ecdsa_server => ECDSAServerDER,
                    rsa_server => RSAServerDER},
    ok = file:write_file(filename:join(Dir, "server.erlang"),
                         io_lib:format("~p.~n", [ErlangTerms])),

    io:format("Certificates written to ~s/~n", [Dir]).

write_cert_key(Dir, Name, ServerDER, CACertDER) ->
    CertDER = proplists:get_value(cert, ServerDER),
    KeyDER = proplists:get_value(key, ServerDER),

    %% Cert chain: leaf + CA
    CertPem = public_key:pem_encode(
                [{'Certificate', CertDER, not_encrypted},
                 {'Certificate', CACertDER, not_encrypted}]),
    ok = file:write_file(filename:join(Dir, Name ++ "_cert.pem"), CertPem),

    %% Private key
    KeyPem = pem_encode_key(KeyDER),
    ok = file:write_file(filename:join(Dir, Name ++ "_key.pem"), KeyPem),
    ok.

pem_encode_key({KeyType, DER}) when is_binary(DER) ->
    PemType = case KeyType of
                  'RSAPrivateKey' -> 'RSAPrivateKey';
                  'ECPrivateKey' -> 'ECPrivateKey';
                  _ -> 'PrivateKeyInfo'
              end,
    public_key:pem_encode([{PemType, DER, not_encrypted}]);
pem_encode_key(Key) when is_tuple(Key) ->
    PemEntry = public_key:pem_entry_encode(element(1, Key), Key),
    public_key:pem_encode([PemEntry]).
