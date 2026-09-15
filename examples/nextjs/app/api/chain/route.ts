// Three calls in order. The interesting question a proxy can answer and code review cannot:
// did the second call actually happen before the third, and what did each one carry?
export async function GET() {
  const trace: Array<{ step: string; status: number; ms: number }> = [];

  const step = async (name: string, url: string, init?: RequestInit) => {
    const t = Date.now();
    const res = await fetch(url, {
      ...init,
      headers: { ...(init?.headers ?? {}), "X-Demo-Trace": `chain-${name}` },
      cache: "no-store",
    });
    await res.arrayBuffer();
    trace.push({ step: name, status: res.status, ms: Date.now() - t });
    return res;
  };

  await step("lookup", "https://api.github.com/zen");
  await step("reserve", "https://httpbin.org/post", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reserve: true, sku: "SKU-77" }),
  });
  await step("confirm", "https://httpbin.org/anything/confirm");

  return Response.json({ trace });
}
