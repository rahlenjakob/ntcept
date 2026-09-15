// Open-Meteo: no API key, no signup, CC BY 4.0.
const CITIES: Record<string, [number, number]> = {
  Stockholm: [59.33, 18.07],
  Helsinki: [60.17, 24.94],
  Lisbon: [38.72, -9.13],
};

export async function GET(req: Request) {
  const city = new URL(req.url).searchParams.get("city") ?? "Stockholm";
  const [lat, lon] = CITIES[city] ?? CITIES.Stockholm;
  const upstream =
    `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}` +
    `&current=temperature_2m,wind_speed_10m&timezone=auto`;

  const started = Date.now();
  const res = await fetch(upstream, {
    headers: { "X-Demo-Trace": `weather-${city}` },
    cache: "no-store",
  });
  const body = await res.json();
  return Response.json({
    upstream,
    status: res.status,
    ms: Date.now() - started,
    current: body.current ?? body,
  });
}
