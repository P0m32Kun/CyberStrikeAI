/** Map captured panel entries to the POST /api/http-flows flows[] contract. */

/**
 * Pick entries that represent a real HTTP flow. Page-context pseudo entries
 * (method "PAGE", captured via "send page context") are not traffic and are
 * skipped.
 */
function syncableEntries(entries) {
  return (entries || []).filter((e) => e && !e.isPageContext && e.url);
}

function headerValueFromLines(lines, name) {
  const list = String(lines || '').split('\n');
  const prefix = name.toLowerCase() + ':';
  for (const line of list) {
    const l = line.toLowerCase();
    if (l.startsWith(prefix)) {
      return line.slice(prefix.length).trim();
    }
  }
  return '';
}

/**
 * One captured entry → one flow object. Field names must match the backend
 * traffic.Flow JSON tags exactly (ts/method/url/status/content_type/
 * req_headers/req_body/resp_headers/resp_body). Bodies are already truncated
 * at capture time (CSAI_LIMITS).
 */
function entryToFlow(entry) {
  return {
    ts: entry.capturedAt || Date.now(),
    method: entry.method || 'GET',
    url: entry.url || '',
    status: entry.responseStatus || 0,
    content_type: headerValueFromLines(entry.responseHeaders, 'content-type'),
    req_headers: entry.requestHeaders || '',
    req_body: entry.requestBody || '',
    resp_headers: entry.responseHeaders || '',
    resp_body: entry.responseBody || '',
  };
}
