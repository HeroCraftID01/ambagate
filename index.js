require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const PROCESSOR_SERVER_URL = process.env.PROCESSOR_SERVER_URL || 'http://localhost:3002';

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('[Server 1] ERROR: SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in .env');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const log = (level, action, message) => {
  const ts = new Date().toISOString();
  const fn = level === 'ERROR' ? 'error' : level === 'WARNING' ? 'warn' : 'log';
  console[fn](`[${ts}] [${level}] [${action}] ${message}`);
};

// AES-256-GCM key derivation (PBKDF2) - must match client crypto.js
const PBKDF2_SALT = Buffer.from('ext-secure-aes-salt-v1');
const PBKDF2_ITERATIONS = 100000;

const deriveKey = (sessionToken) => {
  return crypto.pbkdf2Sync(sessionToken, PBKDF2_SALT, PBKDF2_ITERATIONS, 32, 'sha256');
};

const decryptPayload = (encryptedPayload, sessionToken) => {
  const key = deriveKey(sessionToken);
  const iv = Buffer.from(encryptedPayload.iv, 'base64');
  const dataWithTag = Buffer.from(encryptedPayload.data, 'base64');

  // AES-GCM: auth tag is the last 16 bytes
  const authTag = dataWithTag.slice(dataWithTag.length - 16);
  const ciphertext = dataWithTag.slice(0, dataWithTag.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
};

const encryptResponse = (data, sessionToken) => {
  const key = deriveKey(sessionToken);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    data: Buffer.concat([encrypted, authTag]).toString('base64')
  };
};

// ---- Health check ----
app.get('/health', (req, res) => res.json({ status: 'ok', server: 'gateway' }));

// ---- Auth: Login ----
app.post('/auth/login', async (req, res) => {
  log('INFO', '/auth/login', 'Received login request');
  try {
    const { email, password } = req.body;
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({ email, password });

    if (authError || !authData.user) {
      log('WARNING', '/auth/login', `Login failed for ${email}: ${authError?.message}`);
      return res.status(401).json({ error: authError?.message || 'Login failed' });
    }

    log('INFO', '/auth/login', `Successful login for user ${authData.user.id}`);
    res.json({ session: authData.session, user: authData.user });
  } catch (error) {
    log('ERROR', '/auth/login', `Internal error: ${error.stack}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ---- Auth: Register Public Key ----
app.post('/auth/register_key', async (req, res) => {
  log('INFO', '/auth/register_key', 'Received key registration request');
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing token' });

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      log('WARNING', '/auth/register_key', 'Invalid session');
      return res.status(401).json({ error: 'Invalid session' });
    }

    const { publicKey } = req.body;
    if (!publicKey) return res.status(400).json({ error: 'publicKey is required' });

    const { error: upsertError } = await supabase
      .from('user_keys')
      .upsert(
        { user_id: user.id, public_key: publicKey, private_key: 'N/A_CLIENT_ONLY' },
        { onConflict: 'user_id' }
      );

    if (upsertError) {
      log('ERROR', '/auth/register_key', `Supabase DB Error: ${upsertError.message}`);
      return res.status(500).json({ error: 'Failed to save key: ' + upsertError.message });
    }

    log('INFO', '/auth/register_key', `Key registered for user ${user.id}`);
    res.json({ success: true });
  } catch (error) {
    log('ERROR', '/auth/register_key', `Internal error: ${error.stack}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ---- Auth: Verify Session ----
app.post('/auth/verify', async (req, res) => {
  log('INFO', '/auth/verify', 'Session verification request');
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ valid: false });

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      log('INFO', '/auth/verify', 'Token is invalid or expired');
      return res.status(401).json({ valid: false });
    }

    log('INFO', '/auth/verify', `Token valid for user ${user.id}`);
    res.json({ valid: true, user });
  } catch (error) {
    log('ERROR', '/auth/verify', `Internal error: ${error.stack}`);
    res.status(500).json({ valid: false });
  }
});

// ---- Main Gateway ----
app.post('/gateway', async (req, res) => {
  log('INFO', '/gateway', 'Incoming gateway request');
  try {
    const authHeader = req.headers.authorization;
    const { encryptedPayload, signature } = req.body;

    // Debug: Log what we actually received
    log('INFO', '/gateway', `Auth header present: ${!!authHeader}`);
    log('INFO', '/gateway', `Body keys: ${Object.keys(req.body || {}).join(', ')}`);
    log('INFO', '/gateway', `encryptedPayload present: ${!!encryptedPayload}, type: ${typeof encryptedPayload}`);
    log('INFO', '/gateway', `signature present: ${!!signature}, type: ${typeof signature}`);

    if (!authHeader || !encryptedPayload || !signature) {
      const missing = [];
      if (!authHeader) missing.push('authHeader');
      if (!encryptedPayload) missing.push('encryptedPayload');
      if (!signature) missing.push('signature');
      log('WARNING', '/gateway', `Missing fields: ${missing.join(', ')}`);
      return res.status(400).json({ error: `Bad Request: missing ${missing.join(', ')}` });
    }

    const token = authHeader.replace('Bearer ', '');

    // 1. Verify JWT with Supabase
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      log('WARNING', '/gateway', 'Unauthorized: Invalid token');
      return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
    }

    // 2. Fetch user's RSA Public Key for signature verification
    const { data: keyData, error: keyError } = await supabase
      .from('user_keys')
      .select('public_key')
      .eq('user_id', user.id)
      .single();

    if (keyError || !keyData?.public_key) {
      log('WARNING', '/gateway', `Public key not found for user ${user.id}`);
      return res.status(400).json({ error: 'Public key not registered. Please re-login.' });
    }

    // 3. Verify digital signature of the encrypted payload
    let isSignatureValid = false;
    try {
      const verify = crypto.createVerify('sha256');
      verify.update(JSON.stringify(encryptedPayload));
      verify.end();
      isSignatureValid = verify.verify(keyData.public_key, Buffer.from(signature, 'base64'));
    } catch (verifyErr) {
      log('ERROR', '/gateway', `Signature verification crashed: ${verifyErr.message}`);
    }

    if (!isSignatureValid) {
      log('WARNING', '/gateway', `Invalid signature for user ${user.id}`);
      return res.status(401).json({ error: 'Invalid digital signature.' });
    }

    // 4. Decrypt AES-256-GCM payload using session token
    let decryptedPayload;
    try {
      decryptedPayload = decryptPayload(encryptedPayload, token);
    } catch (decryptErr) {
      log('ERROR', '/gateway', `AES decryption failed: ${decryptErr.message}`);
      return res.status(400).json({ error: 'Payload decryption failed.' });
    }

    log('INFO', '/gateway', `Signature & decryption OK → action='${decryptedPayload.action}' for user=${user.id}`);

    // 5. Forward decrypted JSON to Server 2
    const processorResponse = await fetch(`${PROCESSOR_SERVER_URL}/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: user.id, requestData: decryptedPayload, sessionToken: token }),
    });

    if (!processorResponse.ok) {
      const errBody = await processorResponse.json().catch(() => ({}));
      log('ERROR', '/gateway', `Server 2 returned ${processorResponse.status}: ${JSON.stringify(errBody)}`);
      return res.status(502).json(errBody);
    }

    const processorData = await processorResponse.json();

    // 6. Encrypt the response with AES-256-GCM before sending back
    const encryptedResponse = encryptResponse(processorData, token);
    log('INFO', '/gateway', `Response encrypted and returned to client`);
    res.json({ encryptedData: encryptedResponse });

  } catch (error) {
    log('ERROR', '/gateway', `Unhandled error: ${error.stack}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  log('INFO', 'SYSTEM', `Gateway running on port ${PORT}`);
  log('INFO', 'SYSTEM', `Forwarding to Processor at ${PROCESSOR_SERVER_URL}`);
});
