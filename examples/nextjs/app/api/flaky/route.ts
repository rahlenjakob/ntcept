// Fails on purpose, so `ntcept wait --errors` and `ntcept ls --status 503` have something
// to find.
export async function GET() {
  const res = await fetch("https://httpbin.org/status/503", {
    headers: { "X-Demo-Trace": "flaky" },
    cache: "no-store",
  });
  return Response.json({ status: res.status, ok: res.ok }, { status: 200 });
}
