# The proxy stops sending https requests in cleartext

`wget https://example.com/` inside a guest reported `error getting response`,
or a `400 Bad Request` the origin server had written. Both read as "mvm egress
is broken". Egress was fine: `http://` fetched through the same proxy, and a
raw `CONNECT` returned `200 Connection established`.

BusyBox `wget` does not issue `CONNECT` for an `https://` URL behind an HTTP
proxy. It sends the absolute form:

```
GET https://example.com/ HTTP/1.1
Host: example.com
```

`http_forward_target` resolved that to `example.com:443` — the right port — and
`serve_http_forward` then wrote the head to it. Nothing on either side speaks
TLS on that path: the in-guest proxy relays bytes so the host can authorize and
log every connection, and the host relays them onward untouched. So a plaintext
HTTP request went to a port expecting TLS. The origin answered with an error or
hung up, which is the symptom; the request line, the `Host` header and every
other header had already crossed the network in the clear, which is the part
that mattered.

The proxy now refuses instead, with the reason in the status line because that
is the only part most clients print:

```
HTTP/1.1 501 Not Implemented (https absolute-URI needs CONNECT or SOCKS)
```

Both transports that do work are unchanged: `CONNECT` (curl, and anything else
that tunnels) and SOCKS5. `http://` absolute-form requests are still forwarded,
which is what a forward proxy is for.

The live HTTPS BDD witnesses now exercise that supported path with the pinned,
multi-architecture `curlimages/curl:8.21.0` image. This changes only the client
used by the witness: curl establishes `CONNECT` before its TLS handshake, while
the proxy continues to refuse BusyBox `wget`'s plaintext HTTPS absolute form.
A repository regression keeps all seven live HTTPS commands on the pinned
CONNECT-capable client.

`http_forward_target` returns `HttpForwardTarget { target, tls }` rather than a
bare string. The scheme decided the port and was then thrown away, which is how
the two cases became indistinguishable one line later.

Witnesses: `an_https_absolute_uri_is_refused_without_opening_a_flow` (the host
end of a live FlowMux session receives no frame at all, so nothing was opened
and nothing was written — red against the old forward),
`a_plain_http_absolute_uri_still_opens_a_flow`,
`http_forward_target_uses_port_443_for_https_and_reports_tls`, and
`an_explicit_port_does_not_hide_the_https_scheme`. Confirmed live on HVF: the
refusal reaches `wget` verbatim and a raw `CONNECT` still returns 200.
