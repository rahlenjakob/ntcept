# ntcept example: a Next.js app with a database behind it

A small app that calls third-party APIs, a postgres, and a redis. It exists to be run under
ntcept, and to show what ntcept makes of traffic that is not HTTP.

```bash
docker compose up -d          # postgres and redis
ntcept run -- npm run dev     # the app, on your machine
open http://localhost:3210
```

Press the buttons, then look:

```bash
ntcept ls
ntcept show <id>
```

## Why the app is not in the compose file

ntcept supervises a command you launch. The point of this example is a process on your own
machine talking to services somewhere else, which is what a dev setup actually looks like. Put
the app in compose too and it would be on a network ntcept was never asked to watch.

## Why the ports are wrong on purpose

Postgres is on **15432** and redis on **16379**, not 5432 and 6379. A decoder that recognises a
database by its port works in an example and nowhere else — compose maps ports, a second postgres
lands on 5433, a managed service hands out whatever it likes. ntcept recognises these from what
is on the wire, and the odd ports are how you can tell that it does.

## What the database traffic looks like

The interesting one is `postgres · find orders`. The driver does not send the query with the
values in it — it sends the statement once with placeholders and the values separately, which is
what every driver and ORM does:

```
out Startup user=shop database=shop
in  Auth SASL requested (SCRAM-SHA-256)
out PasswordMessage (51 bytes, not shown)
in  AuthOK
out Parse "select id, email, total, status from orders where email = $1 and total >= $2 order by id"
out Bind  "select id, email, total, status from orders …" [$1=grace@example.com, $2=1000]
out Execute …
in  RowDescription id, email, total, status
in  DataRow 2, grace@example.com, 12750, paid
in  CommandComplete SELECT 1
```

`Bind` is the line that matters. Without it you know a query ran against `$1`, and not which
customer it was for.

`postgres · duplicate insert` violates a unique index, and the answer comes back as the thing you
would want to read:

```
in  ErrorResponse ERROR 23505 duplicate key value violates unique constraint
    "orders_one_pending_per_email" detail: Key (email)=(alan@example.com) already exists.
```

`redis · set and read back` shows the commands as you would type them:

```
out CLIENT SETINFO LIB-NAME node-redis
out SET last-order 2026-09-15T10:43:34.359Z EX 60
in  OK
out GET last-order
in  2026-09-15T10:43:34.359Z
```

## Why interception happens below the socket API

Node ignores proxy environment variables for its own `https` module — a proxy-based tool would run
this app fine and capture nothing at all. ntcept intercepts below the socket API instead, so Node's
`https`, `fetch`, the `pg` driver and the `redis` client are all caught the same way, whatever they
honour.

Postgres and redis here speak plaintext, which is normal for a local dev database. A managed
database over TLS would show the handshake and then `SSLRequest (the rest of this connection is
encrypted)` — ntcept terminates TLS for HTTP, not for postgres.

## Tidying up

```bash
docker compose down -v
```
