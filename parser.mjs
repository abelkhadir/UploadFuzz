import fs from 'fs';

export async function parseRequestFile(file) {
  const raw = fs.readFileSync(file, "utf8");

  // URL
  const url = raw.match(/curl '([^']+)'/)?.[1];


  let method = "POST"; // default
  const methodMatch = raw.match(/-X (\w+)/);
  if (methodMatch) method = methodMatch[1];
  else if (raw.includes("--data-raw") || raw.includes("--data")) method = "POST";


  // headers
  const headers = {};
  [...raw.matchAll(/-H '([^:]+):\s*([^']+)'/g)]
    .forEach(([, k, v]) => headers[k.toLowerCase()] = v);

  // content-type + boundary
  const contentTypeMulti = headers["content-type"];
  const boundary = contentTypeMulti?.match(/boundary=(.+)/)?.[1];

  // body
  const body = raw.match(/--data-raw \$'([\s\S]*?)'\s*\\/);
  const bodyRaw = body ? body[1].replace(/\\r\\n/g, "\r\n") : "";

  // parse multipart
  let formDame;
  let formDataName = ""
  let contentType;
  if (boundary) {
    bodyRaw
      .split(`--${boundary}`)
      .filter(p => p.includes("Content-Disposition"))
      .forEach(p => {
        const name = p.match(/name="([^"]+)"/)?.[1];
        const type = p.match(/Content-Type:\s*([^\r\n]+)/)?.[1];
        if (name) {
          formDataName = name;
          contentType = type;
        }
      });
  }

  return ({
    method,
    url,
    contentType,
    formDataName
  });
}
