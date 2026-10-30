// Shared HTTP helpers. No runtime-specific imports: plain node + Workers.
const BASE_HEADERS = { "x-content-type-options": "nosniff" };

export function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...BASE_HEADERS,
      ...extra,
    },
  });
}

export function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      ...BASE_HEADERS,
    },
  });
}

// OAuth endpoints take application/x-www-form-urlencoded bodies; JSON is
// accepted as a convenience for scripted clients. Returns null on bad input.
export async function parseFormOrJson(request) {
  const type = request.headers.get("content-type") || "";
  try {
    if (type.includes("application/json")) return await request.json();
    const form = await request.formData();
    return Object.fromEntries(form.entries());
  } catch {
    return null;
  }
}
