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

// ============================================================
// CRYPTO v3 — Matches client crypto.js exactly
// Protocol: HKDF-SHA-384 + AES-256-GCM + RSA-PSS-4096/SHA-512
// ============================================================

const HKDF_INFO_REQUEST  = Buffer.from('ext-request-v3');
const HKDF_INFO_RESPONSE = Buffer.from('ext-response-v3');

/**
 * Compute IKM = deviceKey XOR sessionToken (32 bytes)
 * Matches client: for (let i = 0; i < 32; i++) ikm[i] = (deviceBytes[i] ?? 0) ^ (tokenBytes[i % tokenBytes.length] ?? 0)
 */
const computeIKM = (deviceKeyB64, sessionToken) => {
  const deviceBytes = Buffer.from(deviceKeyB64, 'base64');
  const tokenBytes  = Buffer.from(sessionToken, 'utf8');
  const ikm = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    ikm[i] = (deviceBytes[i] ?? 0) ^ (tokenBytes[i % tokenBytes.length] ?? 0);
  }
  return ikm;
};

/** HKDF-SHA-384 key derivation — matches client's deriveRequestKey */
const hkdfDeriveKey = (ikm, salt, info) => {
  return new Promise((resolve, reject) => {
    crypto.hkdf('sha384', ikm, salt, info, 32, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(Buffer.from(derivedKey));
    });
  });
};

/**
 * Decrypt payload bundle { v, rid, ts, iv, ct } (base64-encoded JSON)
 * Matches client's encryptPayload / HKDF_INFO_REQUEST
 */
const decryptPayloadV3 = async (payloadB64, deviceKeyB64, sessionToken) => {
  const bundle = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
  if (bundle.v !== 3) throw new Error('Unsupported payload version: ' + bundle.v);

  const iv  = Buffer.from(bundle.iv, 'base64');  // 12-byte nonce
  const ct  = Buffer.from(bundle.ct, 'base64');  // ciphertext + 16-byte GCM auth tag

  const ikm        = computeIKM(deviceKeyB64, sessionToken);
  const aesKey     = await hkdfDeriveKey(ikm, iv, HKDF_INFO_REQUEST);

  const authTag    = ct.slice(ct.length - 16);
  const ciphertext = ct.slice(0, ct.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
};

/**
 * Encrypt response using HKDF_INFO_RESPONSE, returns base64 bundle string.
 * Matches client's decryptResponse.
 */
const encryptResponseV3 = async (data, deviceKeyB64, sessionToken) => {
  const iv     = crypto.randomBytes(12);
  const ikm    = computeIKM(deviceKeyB64, sessionToken);
  const aesKey = await hkdfDeriveKey(ikm, iv, HKDF_INFO_RESPONSE);

  const cipher    = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const plaintext = Buffer.from(JSON.stringify(data), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag   = cipher.getAuthTag();
  const ct        = Buffer.concat([encrypted, authTag]);

  const bundle = {
    v:  3,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
  };

  return Buffer.from(JSON.stringify(bundle)).toString('base64');
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
    // Client sends: { payload: payloadB64, sig: signatureB64, dk: deviceKeyB64 }
    const { payload: payloadB64, sig: signature, dk: deviceKeyB64 } = req.body;

    log('INFO', '/gateway', `Auth header: ${!!authHeader}, payload: ${!!payloadB64}, sig: ${!!signature}, dk: ${!!deviceKeyB64}`);

    const missing = [];
    if (!authHeader)   missing.push('Authorization header');
    if (!payloadB64)   missing.push('payload');
    if (!signature)    missing.push('sig');
    if (missing.length > 0) {
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
      return res.status(403).json({
        error: 'Public key not registered',
        code: 'KEY_NOT_REGISTERED',
        message: 'Kunci keamanan belum terdaftar. Silakan logout dan login kembali.'
      });
    }

    // 3. Verify RSA-PSS/SHA-512 digital signature
    //    Client signs the raw payloadB64 *string bytes* — so we verify the same.
    let isSignatureValid = false;

    if (signature === 'FALLBACK_SIGNATURE') {
      log('WARNING', '/gateway', `User ${user.id} using FALLBACK_SIGNATURE mode`);
      isSignatureValid = true;
    } else {
      try {
        // RSA-PSS with SHA-512 and saltLength=64 — must match client signPayload()
        isSignatureValid = crypto.verify(
          'SHA512',
          Buffer.from(payloadB64, 'utf8'),  // sign the raw base64 string bytes
          {
            key: keyData.public_key,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 64,
          },
          Buffer.from(signature, 'base64')
        );
      } catch (verifyErr) {
        log('ERROR', '/gateway', `RSA-PSS verify crashed: ${verifyErr.message}`);
      }
    }

    if (!isSignatureValid) {
      log('WARNING', '/gateway', `Invalid RSA-PSS signature for user ${user.id}`);
      return res.status(401).json({ error: 'Invalid digital signature.' });
    }

    // 4. Decrypt AES-256-GCM payload (v3 bundle) using HKDF-SHA-384
    let decryptedPayload;
    try {
      if (signature === 'FALLBACK_SIGNATURE' || !deviceKeyB64) {
        // Fallback: payload is plain base64 JSON
        log('WARNING', '/gateway', 'Fallback decryption (no deviceKey / FALLBACK_SIGNATURE)');
        decryptedPayload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
      } else {
        decryptedPayload = await decryptPayloadV3(payloadB64, deviceKeyB64, token);
      }
    } catch (decryptErr) {
      log('ERROR', '/gateway', `Decryption failed: ${decryptErr.message}`);
      return res.status(400).json({ error: 'Payload decryption failed: ' + decryptErr.message });
    }

    log('INFO', '/gateway', `OK → action='${decryptedPayload.action}' user=${user.id}`);

    // 5. Forward decrypted JSON to Server 2
    const processorResponse = await fetch(`${PROCESSOR_SERVER_URL}/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: user.id, requestData: decryptedPayload, sessionToken: token }),
    });

    if (!processorResponse.ok) {
      const errBody = await processorResponse.json().catch(() => ({}));
      log('ERROR', '/gateway', `Server 2 error ${processorResponse.status}: ${JSON.stringify(errBody)}`);
      return res.status(502).json(errBody);
    }

    const processorData = await processorResponse.json();

    // 6. Encrypt response with HKDF v3 — matches client decryptResponse()
    //    Response field is 'payload' (base64 bundle string) — matches api.js check
    let responsePayload;
    if (signature === 'FALLBACK_SIGNATURE' || !deviceKeyB64) {
      // Fallback mode: plain base64 JSON, wrapped in { payload } so client logic still works
      const fallbackBundle = {
        v: 3,
        iv: 'fallback',
        ct: Buffer.from(JSON.stringify(processorData)).toString('base64')
      };
      responsePayload = Buffer.from(JSON.stringify(fallbackBundle)).toString('base64');
    } else {
      responsePayload = await encryptResponseV3(processorData, deviceKeyB64, token);
    }

    log('INFO', '/gateway', `Response encrypted (v3) and returned to client`);
    res.json({ payload: responsePayload });

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
