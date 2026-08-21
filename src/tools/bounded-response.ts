const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;

export async function readBoundedResponseText(
  response: Response,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES
): Promise<string> {
  const contentLength = response.headers.get("content-length");
  if (contentLength && /^[0-9]+$/.test(contentLength) && Number(contentLength) > maxBytes) {
    throw new Error(`response advertised more than ${maxBytes} bytes`);
  }
  if (!response.body) {
    throw new Error("response body was missing");
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel("response-size limit exceeded").catch(() => {});
        throw new Error(`response exceeded ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
}

export async function readBoundedJsonResponse(
  response: Response,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES
): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  const mediaType = contentType.split(";", 1)[0].trim().toLowerCase();
  if (mediaType !== "application/json") {
    throw new Error(`unexpected response content type: ${contentType || "(missing)"}`);
  }
  return JSON.parse(await readBoundedResponseText(response, maxBytes));
}
