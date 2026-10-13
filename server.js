const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {initializeApp} = require('firebase-admin/app');
const {getAuth} = require('firebase-admin/auth');

const projectId = process.env.FIREBASE_PROJECT_ID;
const iprogApiToken = process.env.IPROG_API_TOKEN;
const port = Number(process.env.PORT || 10000);
const root = __dirname;
const allowedOrigins = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);
const iprogSmsEndpoint = 'https://www.iprogsms.com/api/v1/sms_messages';
const warningLimit = 4;
const violationLimit = 5;
const allowedRoles = new Set(['guidance', 'counselor', 'guidance_counselor', 'guidance_office']);
const mimeTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jfif': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ttf': 'font/ttf',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};
const privatePaths = new Set([
  '.env',
  '.git',
  '.firebase',
  'firebase.json',
  'firestore.indexes.json',
  'firestore.rules',
  'functions',
  'node_modules',
  'package-lock.json',
  'package.json',
]);

if (!projectId?.trim()) throw new Error('FIREBASE_PROJECT_ID must be set in the environment.');
if (!iprogApiToken?.trim()) throw new Error('IPROG_API_TOKEN must be set in the environment.');
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be a valid port number.');
}
if (!allowedOrigins.length) throw new Error('CORS_ORIGINS must contain at least one allowed origin.');

initializeApp({projectId});

function sendJson(response, status, payload){
  response.writeHead(status, {'Content-Type': 'application/json; charset=utf-8'});
  response.end(JSON.stringify(payload));
}

function setCorsHeaders(request, response){
  const origin = request.headers.origin;
  if (!origin) return;
  if (allowedOrigins.includes('*')) {
    response.setHeader('Access-Control-Allow-Origin', '*');
  } else if (allowedOrigins.includes(origin)) {
    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Vary', 'Origin');
  }
  response.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
}

async function readJsonBody(request){
  const chunks = [];
  let size = 0;
  for await (const chunk of request){
    size += chunk.length;
    if(size > 16 * 1024) throw new Error('Request body is too large.');
    chunks.push(chunk);
  }
  try{
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }catch(error){
    throw new Error('Request body must be valid JSON.');
  }
}

async function getAuthorizedRole(idToken, uid){
  const roleUrl = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/users/${encodeURIComponent(uid)}`;
  const response = await fetch(roleUrl, {
    headers: {'Authorization': `Bearer ${idToken}`}
  });
  if(!response.ok) throw new Error(`Role lookup failed with status ${response.status}.`);
  const userDocument = await response.json();
  return String(userDocument.fields?.role?.stringValue || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

function validateSmsRequest(body){
  if(!body || typeof body !== 'object' || Array.isArray(body)){
    return 'Request body must be a JSON object.';
  }
  if(!Number.isInteger(body.violationCount) ||
    (body.violationCount !== warningLimit && body.violationCount < violationLimit)){
    return 'SMS is only sent for the warning or void thresholds.';
  }
  if(!Array.isArray(body.phoneNumbers) ||
    body.phoneNumbers.length < 1 ||
    body.phoneNumbers.length > 2 ||
    body.phoneNumbers.some(phone => typeof phone !== 'string' || !phone.trim() || phone.length > 40)){
    return 'One or two valid phone numbers are required.';
  }
  if(typeof body.studentName !== 'string' || !body.studentName.trim() || body.studentName.length > 120){
    return 'A valid student name is required.';
  }
  if(typeof body.violationType !== 'string' || body.violationType.length > 180){
    return 'A valid violation type is required.';
  }
  return null;
}

async function sendViolationSms(request, response){
  if(request.method !== 'POST'){
    response.setHeader('Allow', 'POST');
    return sendJson(response, 405, {error: 'Method not allowed.'});
  }

  const authorization = request.headers.authorization || '';
  const tokenMatch = authorization.match(/^Bearer (.+)$/i);
  if(!tokenMatch) return sendJson(response, 401, {error: 'Authentication required.'});

  let user;
  try{
    user = await getAuth().verifyIdToken(tokenMatch[1]);
  }catch(error){
    return sendJson(response, 401, {error: 'Authentication failed.'});
  }

  let role;
  try{
    role = await getAuthorizedRole(tokenMatch[1], user.uid);
  }catch(error){
    console.error('Could not verify SMS sender role:', error.message);
    return sendJson(response, 503, {error: 'Could not verify SMS sender permissions.'});
  }
  if(!allowedRoles.has(role)) return sendJson(response, 403, {error: 'Permission denied.'});

  let body;
  try{
    body = await readJsonBody(request);
  }catch(error){
    return sendJson(response, 400, {error: error.message});
  }
  const validationError = validateSmsRequest(body);
  if(validationError) return sendJson(response, 400, {error: validationError});

  const message = body.violationCount === warningLimit
    ? `Warning: ${body.studentName.trim()} has reached 4 violations. Latest violation: ${body.violationType.trim()}. Please contact the school.`
    : `Status update: ${body.studentName.trim()} has reached 5 or more violations. Scholarship status: VOID.`;
  const phoneNumbers = [...new Set(body.phoneNumbers.map(phone => phone.trim()))];

  try{
    for(const phoneNumber of phoneNumbers){
      const smsResponse = await fetch(iprogSmsEndpoint, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          api_token: process.env.IPROG_API_TOKEN,
          phone_number: phoneNumber,
          message
        })
      });
      if(!smsResponse.ok){
        console.error('IPROG SMS request failed with status:', smsResponse.status);
        return sendJson(response, 502, {error: 'IPROG could not send the violation SMS.'});
      }
    }
    return sendJson(response, 200, {sent: phoneNumbers.length});
  }catch(error){
    console.error('IPROG SMS request failed:', error);
    return sendJson(response, 502, {error: 'IPROG SMS request failed.'});
  }
}

async function serveStaticFile(request, response, pathname){
  let decodedPath;
  try{
    decodedPath = decodeURIComponent(pathname);
  }catch(error){
    return sendJson(response, 400, {error: 'Invalid URL path.'});
  }

  const relativePath = decodedPath === '/' ? 'index.html' : decodedPath.replace(/^\/+/, '');
  const segments = relativePath.split(/[\\/]/);
  if(segments.some(segment => !segment || segment.startsWith('.') || privatePaths.has(segment))){
    return sendJson(response, 404, {error: 'Not found.'});
  }

  const filePath = path.resolve(root, relativePath);
  if(!filePath.startsWith(`${root}${path.sep}`)){
    return sendJson(response, 404, {error: 'Not found.'});
  }
  const contentType = mimeTypes[path.extname(filePath).toLowerCase()];
  if(!contentType) return sendJson(response, 404, {error: 'Not found.'});

  try{
    const file = await fs.promises.readFile(filePath);
    response.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': file.length,
      'X-Content-Type-Options': 'nosniff'
    });
    return response.end(request.method === 'HEAD' ? undefined : file);
  }catch(error){
    if(error.code === 'ENOENT' || error.code === 'EISDIR'){
      return sendJson(response, 404, {error: 'Not found.'});
    }
    console.error('Could not serve local app file:', error);
    return sendJson(response, 500, {error: 'Could not load the requested file.'});
  }
}

const server = http.createServer(async (request, response) => {
  let url;
  try{
    url = new URL(request.url, `http://${request.headers.host || `0.0.0.0:${port}`}`);
  }catch(error){
    return sendJson(response, 400, {error: 'Invalid request URL.'});
  }

  if(url.pathname === '/api/violation-sms'){
    setCorsHeaders(request, response);
    if(request.method === 'OPTIONS'){
      if(request.headers.origin && !allowedOrigins.includes('*') && !allowedOrigins.includes(request.headers.origin)){
        return sendJson(response, 403, {error: 'Origin not allowed.'});
      }
      response.writeHead(204);
      return response.end();
    }
    return sendViolationSms(request, response);
  }
  if(request.method !== 'GET' && request.method !== 'HEAD'){
    response.setHeader('Allow', 'GET, HEAD');
    return sendJson(response, 405, {error: 'Method not allowed.'});
  }
  return serveStaticFile(request, response, url.pathname);
});

server.listen(port, '0.0.0.0', () => {
  console.log(`App server listening on 0.0.0.0:${port}`);
});
