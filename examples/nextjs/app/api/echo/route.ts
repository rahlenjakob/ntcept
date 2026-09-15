// A POST with a real body, so there is something worth reading in `ntcept show`.
export async function POST(req: Request) {
  const payload = await req.json().catch(() => ({}));
  const order = {
    order: `A-${Math.floor(Math.random() * 900 + 100)}`,
    amount: payload.amount ?? 2500,
    currency: "EUR",
    note: payload.note ?? "placed from the example app",
  };

  const res = await fetch("https://httpbin.org/post", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // Deliberately a credential: ntcept masks it on the way into the buffer while still
      // sending the real value upstream.
      Authorization: "Bearer sk_live" + "_exampleappnotarealkey0123",
      "X-Demo-Trace": "echo",
    },
    body: JSON.stringify(order),
    cache: "no-store",
  });
  const body = await res.json();
  return Response.json({ sent: order, status: res.status, seenByUpstream: body.json });
}
