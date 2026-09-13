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
    
    let finalPublicKey = publicKey;
    
    // If client sends FALLBACK_REQUEST (Web Crypto not available), generate key pair on server
    if (!publicKey || publicKey === 'FALLBACK_REQUEST') {
      log('WARNING', '/auth/register_key', `Client cannot generate keys (no Web Crypto), generating server-side for user ${user.id}`);
      
      try {
        // Generate RSA key pair on server side for fallback clients
        const { publicKey: serverPubKey, privateKey: serverPrivKey } = crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        
        finalPublicKey = serverPubKey;
        
        // Store both keys since client cannot generate them
        const { error: upsertError } = await supabase
          .from('user_keys')
          .upsert(
            { user_id: user.id, public_key: serverPubKey, private_key: serverPrivKey },
            { onConflict: 'user_id', ignoreDuplicates: false }
          );

        if (upsertError) {
          log('ERROR', '/auth/register_key', `Supabase DB Error: ${upsertError.message}`);
          return res.status(500).json({ error: 'Failed to save key: ' + upsertError.message });
        }

        log('INFO', '/auth/register_key', `Server-generated key pair registered for user ${user.id}`);
        return res.json({ success: true, serverGenerated: true, privateKey: serverPrivKey });
        
      } catch (genError) {
        log('ERROR', '/auth/register_key', `Failed to generate key pair: ${genError.message}`);
        return res.status(500).json({ error: 'Failed to generate key pair' });
      }
    }
    
    // Normal flow: client provided public key
    if (!finalPublicKey) return res.status(400).json({ error: 'publicKey is required' });

    // Use upsert to handle both insert and update cases
    const { error: upsertError } = await supabase
      .from('user_keys')
      .upsert(
        { user_id: user.id, public_key: finalPublicKey, private_key: 'N/A_CLIENT_ONLY' },
        { onConflict: 'user_id', ignoreDuplicates: false }
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

// ---- Auth: Check Key Registration Status ----
app.post('/auth/check_key', async (req, res) => {
  log('INFO', '/auth/check_key', 'Checking key registration status');
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing token' });

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      log('WARNING', '/auth/check_key', 'Invalid session');
      return res.status(401).json({ error: 'Invalid session' });
    }

    const { data: keyData, error: keyError } = await supabase
      .from('user_keys')
      .select('public_key, private_key')
      .eq('user_id', user.id)
      .single();

    if (keyError && keyError.code !== 'PGRST116') {
      log('ERROR', '/auth/check_key', `Supabase error: ${keyError.message}`);
      return res.status(500).json({ error: 'Database error' });
    }

    const hasKey = !!keyData?.public_key;
    const isServerGenerated = hasKey && keyData.private_key !== 'N/A_CLIENT_ONLY';

    log('INFO', '/auth/check_key', `User ${user.id} - hasKey: ${hasKey}, serverGenerated: ${isServerGenerated}`);
    
    res.json({ 
      hasKey, 
      isServerGenerated,
      privateKey: isServerGenerated ? keyData.private_key : null
    });
  } catch (error) {
    log('ERROR', '/auth/check_key', `Internal error: ${error.stack}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ---- Main Gateway ----
app.post('/gateway', async (req, res) => {
  log('INFO', '/gateway', 'Incoming gateway request');
  try {
    const authHeader = req.headers.authorization;
    const { payload: encryptedPayload, sig: signature } = req.body;

    // Debug: Log what we actually received
    log('INFO', '/gateway', `Auth header present: ${!!authHeader}`);
    log('INFO', '/gateway', `Body keys: ${Object.keys(req.body || {}).join(', ')}`);
    log('INFO', '/gateway', `encryptedPayload present: ${!!encryptedPayload}, type: ${typeof encryptedPayload}`);
    log('INFO', '/gateway', `signature present: ${!!signature}, type: ${typeof signature}`);

    if (!authHeader || !encryptedPayload || !signature) {
      const missing = [];
      if (!authHeader) missing.push('authHeader');
      if (!encryptedPayload) missing.push('payload');
      if (!signature) missing.push('sig');
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
      log('WARNING', '/gateway', `Public key not found for user ${user.id} - keyError: ${keyError?.code}`);
      return res.status(403).json({ 
        error: 'Public key not registered', 
        code: 'KEY_NOT_REGISTERED',
        message: 'Kunci keamanan belum terdaftar. Silakan logout dan login kembali untuk mendaftarkan kunci baru.'
      });
    }

    // 3. Verify digital signature of the encrypted payload
    let isSignatureValid = false;
    
    // Check if using fallback mode (for non-HTTPS environments like CefSharp)
    if (signature === 'FALLBACK_SIGNATURE') {
      log('WARNING', '/gateway', `User ${user.id} using FALLBACK mode (no Web Crypto API)`);
      isSignatureValid = true; // Accept fallback in development/non-HTTPS environments
    } else {
      try {
        const verify = crypto.createVerify('sha256');
        verify.update(JSON.stringify(encryptedPayload));
        verify.end();
        isSignatureValid = verify.verify(keyData.public_key, Buffer.from(signature, 'base64'));
      } catch (verifyErr) {
        log('ERROR', '/gateway', `Signature verification crashed: ${verifyErr.message}`);
      }
    }

    if (!isSignatureValid) {
      log('WARNING', '/gateway', `Invalid signature for user ${user.id}`);
      return res.status(401).json({ error: 'Invalid digital signature.' });
    }

    // 4. Decrypt AES-256-GCM payload using session token
    let decryptedPayload;
    try {
      // Check if using fallback encryption
      if (encryptedPayload.iv === 'fallback') {
        log('WARNING', '/gateway', 'Using fallback decryption (no AES-GCM)');
        decryptedPayload = JSON.parse(Buffer.from(encryptedPayload.data, 'base64').toString('utf8'));
      } else {
        decryptedPayload = decryptPayload(encryptedPayload, token);
      }
    } catch (decryptErr) {
      log('ERROR', '/gateway', `Decryption failed: ${decryptErr.message}`);
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
    let encryptedResponse;
    if (signature === 'FALLBACK_SIGNATURE') {
      // Fallback mode - just use base64
      encryptedResponse = {
        iv: 'fallback',
        data: Buffer.from(JSON.stringify(processorData)).toString('base64')
      };
    } else {
      encryptedResponse = encryptResponse(processorData, token);
    }
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
