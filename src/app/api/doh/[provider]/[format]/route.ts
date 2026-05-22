import { NextRequest } from 'next/server';
import { handleDoH } from '@/lib/doh';

export const runtime = 'edge';

// Format-specific provider endpoint: /api/doh/<provider>/<format>
// e.g. /api/doh/google/resolve (JSON) or /api/doh/google/dns-query (wire).

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ provider: string; format: string }> }
) {
  const { provider, format } = await params;
  return handleDoH(request, provider, format);
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ provider: string; format: string }> }
) {
  // RFC 8484 wire-format POST (Content-Type: application/dns-message).
  const { provider, format } = await params;
  return handleDoH(request, provider, format);
}

export async function HEAD(
  request: NextRequest,
  { params }: { params: Promise<{ provider: string; format: string }> }
) {
  const { provider, format } = await params;
  return handleDoH(request, provider, format);
}
