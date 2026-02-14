# Rustls-jls
This is a fork of [Rustls](https://github.com/rustls/rustls) which implements the [JLS](https://github.com/JimmyHuang454/JLS) protocol.

# Implementation detail
- Use JLS v3 protocol to authenticate clienthello and servehello
- The authentication result is stored in `jls_authed` variable. `Some(true)` for a successful authentication and `Some(false)` for 
a failed authentication. `None` for not handshaking.
- For a client, a successful authentication will skip certificates verification. A failed one will not and it degenerate to be a normal tls connection.
- For a server, authentication result makes no difference except `jls_authed` variable
- No port forward is implemented since rustls makes no IO operation. It's better to implement in
tokio-rustls.
# Example
## client
see [client](./examples/src/bin/simplejlsclient.rs).

```
RUST_LOG=debug cargo run --bin simplejlsclient
```
## server
see [server](./examples/src/bin/jlsserver-mio.rs).
```
RUST_LOG=debug cargo run --bin jlsserver-mio -- --certs ./test-ca/ecdsa/end.cert --key ./test-ca/ecdsa/end.key --port 4443 echo
```



