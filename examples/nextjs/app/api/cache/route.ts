import { NextRequest } from "next/server";
import { createClient } from "redis";

// Redis on a port nothing expects, speaking RESP3 — which is what every recent client negotiates
// with HELLO the moment it connects.
const URL = process.env.REDIS_URL ?? "redis://127.0.0.1:16379";

export async function GET(req: NextRequest) {
  const key = req.nextUrl.searchParams.get("key") ?? "last-order";
  const client = createClient({ url: URL });
  await client.connect();
  try {
    await client.set(key, new Date().toISOString(), { EX: 60 });
    const value = await client.get(key);
    const size = await client.dbSize();
    return Response.json({ key, value, keys: size });
  } finally {
    await client.quit();
  }
}
