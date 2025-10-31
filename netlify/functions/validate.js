const crypto = require('crypto');

const EXPIRATION_DATE = new Date(Date.UTC(2026, 0, 1)); // 2026-01-01

exports.handler = async () => {
  try {
    let privateKey = process.env.VLTR_BETA_PRIVATE_KEY;
    if (!privateKey) {
      return {
        statusCode: 500,
        body: 'Server configuration error: Private key not found.',
      };
    }

    // Handle keys stored with escaped newlines ("\n")
    if (privateKey.includes('\\n')) {
      privateKey = privateKey.replace(/\\n/g, '\n');
    }

    // Normalize line endings and trim extra whitespace
    privateKey = privateKey.replace(/\r\n?/g, '\n').trim();

    if (!privateKey.includes('BEGIN') || !privateKey.includes('END')) {
      return {
        statusCode: 500,
        body: 'Server configuration error: Invalid private key format.',
      };
    }

    // Ensure PEM has trailing newline the OpenSSL decoder expects
    if (!privateKey.endsWith('\n')) {
      privateKey += '\n';
    }

    const payload = {
      issue_date: new Date().toISOString(),
      expiration_date: EXPIRATION_DATE.toISOString(),
      issuer: 'VLTR Beta Program',
    };

    const payloadJson = JSON.stringify(payload);
    const signer = crypto.createSign('sha256');
    signer.update(payloadJson);
    signer.end();

    const keyObject = crypto.createPrivateKey({ key: privateKey, format: 'pem', type: 'pkcs8' });
    const signatureBuffer = signer.sign({ key: keyObject, dsaEncoding: 'der' });
    const signature = signatureBuffer.toString('hex');

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload, signature }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: `An error occurred: ${err.message}`,
    };
  }
};

