import { NextRequest, NextResponse } from 'next/server';
import { getProvider, resolveProviderEndpoint } from '@/lib/providers';

// --- Constants & Config ---

const REQUEST_TIMEOUT_MS = 2500; // Upstream timeout (1500ms - 2500ms)
const MAX_QUERY_STRING_LENGTH = 1024;
const MAX_BODY_SIZE = 4096; // RFC 8484 DNS query messages are tiny; cap the POST body
// Allow underscores so SRV/TXT lookups (e.g. _dmarc, _sip._tcp) are accepted.
const ALLOWED_DOMAIN_REGEX = /^[a-zA-Z0-9._-]+$/;

// --- Helpers ---

function getClientIP(req: NextRequest): string {
  // Abstracted IP retrieval - prefer standard headers but don't rely on it for auth
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0] ||
    req.headers.get('cf-connecting-ip') ||
    'unknown'
  );
}

/**
 * SSRF guard for the 'manual' provider.
 *
 * A caller-supplied upstream URL must never be allowed to reach private,
 * loopback or link-local address space (the link-local range also covers
 * cloud metadata endpoints like 169.254.169.254).
 *
 * Both http: and https: are permitted; all other schemes are rejected.
 *
 * Note: full protection requires resolving the hostname, which is not
 * available on the edge runtime. This blocks the common literal-IP and
 * local-hostname cases; DNS-rebinding style attacks are not covered.
 */
function isSafeUpstreamUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }

  // Allow plain HTTP and HTTPS upstreams; reject anything else
  // (file:, ftp:, gopher:, ...).
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;

  // Strip IPv6 brackets and normalize.
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Block obvious local / internal hostnames.
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal')
  ) {
    return false;
  }

  // IPv4 literal checks.
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const a = Number(ipv4[1]);
    const b = Number(ipv4[2]);
    if (a === 0 || a === 10 || a === 127) return false; // this-host / private / loopback
    if (a === 169 && b === 254) return false; // link-local (incl. cloud metadata)
    if (a === 172 && b >= 16 && b <= 31) return false; // private
    if (a === 192 && b === 168) return false; // private
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT (RFC 6598)
    if (a >= 224) return false; // multicast / reserved
    return true;
  }

  // IPv6 literal checks.
  if (host.includes(':')) {
    if (host === '::1' || host === '::') return false; // loopback / unspecified
    if (host.startsWith('fe80')) return false; // link-local
    if (host.startsWith('fc') || host.startsWith('fd')) return false; // unique local
    if (host.startsWith('::ffff:')) return false; // IPv4-mapped
    return true;
  }

  // Regular DNS hostname - allowed.
  return true;
}

interface LogEntry {
  timestamp: string;
  clientIp: string;
  provider: string;
  durationMs: number;
  status: number;
  upstreamUrl?: string;
  error?: string;
  method: string;
}

function logRequest(entry: LogEntry) {
  if (process.env.DEBUG_LOG === 'true' || entry.status >= 400) {
    console.log(JSON.stringify(entry));
  }
}

function validateRequest(url: URL, method: string): NextResponse | null {
  // Validate Query String Length
  if (url.search.length > MAX_QUERY_STRING_LENGTH) {
    return new NextResponse('Query string too long', { status: 414 });
  }

  // RFC 8484 POST (binary wire format) carries the query in the body -
  // there are no query params to validate.
  if (method === 'POST') return null;

  // RFC 8484 GET (base64 dns message) - 'name' is NOT required.
  if (url.searchParams.has('dns')) return null;

  // JSON API request - enforce a valid 'name' param.
  const nameParam = url.searchParams.get('name');
  if (!nameParam || nameParam.length === 0) {
    return new NextResponse('Invalid domain: empty', { status: 400 });
  }
  if (nameParam.length > 253) {
    return new NextResponse('Invalid domain: too long', { status: 400 });
  }
  if (!ALLOWED_DOMAIN_REGEX.test(nameParam)) {
    return new NextResponse('Invalid domain: invalid characters', { status: 400 });
  }
  return null;
}

// --- Main Handler ---

/**
 * Core DoH proxy handler, shared by the bare provider route
 * (/api/doh/<provider>) and the format-specific route
 * (/api/doh/<provider>/<format>).
 */
export async function handleDoH(
  request: NextRequest,
  providerId: string,
  formatSegment?: string
) {
  const startTime = Date.now();
  let upstreamEndpoint = '';
  let responseStatus = 500;

  try {
    // 0. Handle HEAD requests immediately (Health Check)
    if (request.method === 'HEAD') {
      responseStatus = 200;
      const responseHeaders = new Headers();
      responseHeaders.set('Cache-Control', 'no-store, max-age=0');
      responseHeaders.set('Pragma', 'no-cache');
      responseHeaders.set('Expires', '0');
      responseHeaders.set('Vary', 'Accept, Accept-Encoding');
      responseHeaders.set('Access-Control-Allow-Origin', '*');

      return new NextResponse(null, {
        status: 200,
        headers: responseHeaders,
      });
    }

    // 1. Input Validation
    const url = new URL(request.url);
    const validationError = validateRequest(url, request.method);
    if (validationError) {
      responseStatus = validationError.status;
      return validationError;
    }

    // RFC 8484 POST body size guard (DoS protection).
    if (request.method === 'POST') {
      const contentLength = request.headers.get('content-length');
      if (contentLength && Number(contentLength) > MAX_BODY_SIZE) {
        responseStatus = 413;
        return new NextResponse('Payload too large', { status: 413 });
      }
    }

    // 2. Provider Logic
    const provider = getProvider(providerId);
    if (!provider) {
      responseStatus = 404;
      return new NextResponse(`Provider '${providerId}' not found`, { status: 404 });
    }

    // Resolve the upstream endpoint.
    if (providerId === 'custom') {
      const envUrl = process.env.CUSTOM_DOH_URL;
      if (!envUrl) {
        responseStatus = 500;
        return new NextResponse('Configuration Error: CUSTOM_DOH_URL missing', { status: 500 });
      }
      upstreamEndpoint = envUrl;
    } else if (providerId === 'manual') {
      const manualUrl = url.searchParams.get('upstream');
      if (!manualUrl) {
        responseStatus = 400;
        return new NextResponse('Missing "upstream" parameter', { status: 400 });
      }
      // SSRF guard: reject private/loopback/link-local and non-http(s) targets.
      if (!isSafeUpstreamUrl(manualUrl)) {
        responseStatus = 400;
        return new NextResponse('Invalid or disallowed upstream URL', { status: 400 });
      }
      upstreamEndpoint = manualUrl;
    } else {
      // Built-in provider: pick the endpoint for the requested format segment
      // (e.g. /api/doh/google/dns-query), or the default when omitted.
      const resolved = resolveProviderEndpoint(provider, formatSegment);
      if (!resolved) {
        responseStatus = 404;
        return new NextResponse(
          `Endpoint '${formatSegment}' not found for provider '${providerId}'`,
          { status: 404 }
        );
      }
      upstreamEndpoint = resolved;
    }

    // 3. Prepare Upstream Request
    const upstreamUrl = new URL(upstreamEndpoint);

    // Pass through query params for GET, excluding internal ones
    if (request.method === 'GET') {
      url.searchParams.forEach((value, key) => {
        if (key !== 'upstream') { // Don't pass 'upstream' param to the DNS server
           upstreamUrl.searchParams.append(key, value);
        }
      });
    }

    // Consistency Headers
    const headers = new Headers();

    // Forward the client's negotiated content type so both the JSON API
    // (application/dns-json) and the RFC 8484 wire format
    // (application/dns-message) work transparently. Fall back to a sensible
    // default based on the request shape when the client omits Accept.
    const clientAccept = request.headers.get('accept');
    if (clientAccept) {
      headers.set('Accept', clientAccept);
    } else if (request.method === 'POST' || url.searchParams.has('dns')) {
      headers.set('Accept', 'application/dns-message'); // RFC 8484 wire format
    } else {
      headers.set('Accept', 'application/dns-json'); // JSON API
    }
    headers.set('User-Agent', 'Secure-DoH-Proxy/1.0');

    // For RFC 8484 POST the body is the raw DNS query message.
    if (request.method === 'POST') {
      headers.set(
        'Content-Type',
        request.headers.get('content-type') || 'application/dns-message'
      );
    }

    // 4. Fetch with Timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const upstreamResponse = await fetch(upstreamUrl.toString(), {
        method: request.method,
        headers: headers,
        body: request.method === 'POST' ? request.body : undefined,
        signal: controller.signal,
        // @ts-expect-error - 'duplex' is needed for Node/Edge streaming
        duplex: 'half',
      });

      clearTimeout(timeoutId);
      responseStatus = upstreamResponse.status;

      // 5. Secure Response Construction
      const responseHeaders = new Headers();

      // Strict Cache Control (User Req #1)
      responseHeaders.set('Cache-Control', 'no-store, max-age=0');
      responseHeaders.set('Pragma', 'no-cache');
      responseHeaders.set('Expires', '0');
      responseHeaders.set('Vary', 'Accept, Accept-Encoding');
      responseHeaders.set('X-DoH-Proxy-Version', 'v1.1.0');

      // CORS
      responseHeaders.set('Access-Control-Allow-Origin', '*');

      // Forward content type
      const respContentType = upstreamResponse.headers.get('content-type');
      if (respContentType) {
        responseHeaders.set('Content-Type', respContentType);
      }

      return new NextResponse(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders,
      });

    } catch (fetchError: unknown) {
      clearTimeout(timeoutId);
      const isTimeout = (fetchError as Error).name === 'AbortError';
      responseStatus = isTimeout ? 504 : 502;

      return new NextResponse(
        JSON.stringify({ error: isTimeout ? 'Upstream Timeout' : 'Upstream Connection Failed' }),
        {
          status: responseStatus,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

  } catch (err) {
    console.error('Internal Error:', err);
    responseStatus = 500;
    return new NextResponse('Internal Server Error', { status: 500 });
  } finally {
    // 6. Logging (User Req #6)
    logRequest({
      timestamp: new Date().toISOString(),
      clientIp: getClientIP(request),
      provider: providerId,
      durationMs: Date.now() - startTime,
      status: responseStatus,
      upstreamUrl: upstreamEndpoint, // Log the resolved endpoint
      method: request.method
    });
  }
}
