# Erlang/OTP SSL Certificate Selection Bug

Reproducer for a TLS 1.3 certificate selection bug in Erlang/OTP's `ssl` application. When a server is configured with both ECDSA and RSA certificates, it fails to select the correct one based on the client's `signature_algs` — unlike OpenSSL's `s_server`, which handles this correctly.

## Dependencies

- Erlang/OTP (with `ssl`, `crypto`, `public_key` applications)
- OpenSSL CLI (`openssl s_server` is used as a reference)

## Usage

```sh
bash ssl_cert_selection_test.sh
```

This will:

1. Generate test certificates (RSA CA, ECDSA leaf, RSA leaf)
2. Start an OpenSSL `s_server` with both certs and run the client against it (reference)
3. Start an Erlang SSL server with both certs and run the client against it (buggy?)

## Scripts

- `ssl_gen_test_certs.escript` — generates test CA + leaf certs into `test_certs/`
- `ssl_erlang_server.escript` — TLS 1.3 server configured with both ECDSA and RSA certs via `certs_keys`
- `ssl_test_client.escript` — connects twice: once advertising only RSA signature algs, once only ECDSA
- `ssl_cert_selection_test.sh` — orchestrates the full test
