"use client";

import { useState } from "react";

type Call = { label: string; path: string; init?: RequestInit; danger?: boolean };

const CALLS: Call[] = [
  { label: "weather · Stockholm", path: "/api/weather?city=Stockholm" },
  { label: "weather · Lisbon", path: "/api/weather?city=Lisbon" },
  {
    label: "post an order",
    path: "/api/echo",
    init: {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ amount: 4900, note: "from the button" }),
    },
  },
  { label: "three calls in order", path: "/api/chain" },
  { label: "fail on purpose (503)", path: "/api/flaky", danger: true },
  { label: "postgres · find orders", path: "/api/orders?email=grace@example.com&min=1000" },
  {
    label: "postgres · duplicate insert",
    path: "/api/orders",
    danger: true,
    init: {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "alan@example.com", total: 555 }),
    },
  },
  { label: "redis · set and read back", path: "/api/cache?key=last-order" },
];

export default function Page() {
  const [out, setOut] = useState<string>("");
  const [busy, setBusy] = useState<string | null>(null);

  async function run(c: Call) {
    setBusy(c.label);
    setOut(`→ ${c.path}\n`);
    try {
      const res = await fetch(c.path, c.init);
      const body = await res.json();
      setOut(`→ ${c.path}\n← ${res.status}\n\n${JSON.stringify(body, null, 2)}`);
    } catch (e) {
      setOut(`→ ${c.path}\n\nfailed: ${String(e)}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <main>
      <h1>ntcept example</h1>
      <p className="lede">
        Every button makes this app&rsquo;s <em>server</em> call a third-party API. Nothing here
        knows ntcept exists.
      </p>

      <h2>trigger some traffic</h2>
      <div className="row">
        {CALLS.map((c) => (
          <button
            key={c.label}
            onClick={() => run(c)}
            disabled={busy !== null}
            className={c.danger ? "bad" : undefined}
          >
            {busy === c.label ? "…" : c.label}
          </button>
        ))}
      </div>

      {out && <pre>{out}</pre>}

      <footer>
        <p>Now look at what actually went out:</p>
        <p>
          <code>ntcept ls</code> · <code>ntcept show &lt;id&gt;</code> ·{" "}
          <code>ntcept ls --status 503</code> · <code>ntcept diff &lt;a&gt; &lt;b&gt;</code>
        </p>
        <p>
          The <code>Authorization</code> header on the order call reaches httpbin intact, but is
          stored as a fingerprint. <code>ntcept ui</code> opens the inspector.
        </p>
      </footer>
    </main>
  );
}
