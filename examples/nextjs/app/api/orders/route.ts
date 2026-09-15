import { NextRequest } from "next/server";
import { Client } from "pg";

// A parameterised query, which is what a driver actually sends: the SQL goes once with
// placeholders and the values travel separately in a Bind message. Watching this under ntcept is
// the difference between seeing `where email = $1` and seeing which customer was looked up.
const DSN =
  process.env.DATABASE_URL ?? "postgres://shop:shop@127.0.0.1:15432/shop";

async function withClient<T>(fn: (c: Client) => Promise<T>): Promise<T> {
  const client = new Client({ connectionString: DSN });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

export async function GET(req: NextRequest) {
  const email = req.nextUrl.searchParams.get("email") ?? "ada@example.com";
  const min = Number(req.nextUrl.searchParams.get("min") ?? 0);
  const rows = await withClient((c) =>
    c.query(
      "select id, email, total, status from orders where email = $1 and total >= $2 order by id",
      [email, min],
    ),
  );
  return Response.json({ asked: { email, min }, rows: rows.rows });
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const email = body.email ?? "alan@example.com";
  const total = Number(body.total ?? 100);
  try {
    const out = await withClient((c) =>
      c.query(
        "insert into orders (email, total, status) values ($1, $2, 'pending') returning id",
        [email, total],
      ),
    );
    return Response.json({ inserted: out.rows[0] });
  } catch (e: any) {
    // A unique-violation is the interesting case: postgres answers with a severity, a SQLSTATE
    // and a message, and ntcept should show all three rather than a blob of bytes.
    return Response.json(
      { failed: e.message, sqlstate: e.code, detail: e.detail },
      { status: 409 },
    );
  }
}
