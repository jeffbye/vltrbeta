const crypto = require('crypto');

const EXPIRATION_DATE = new Date(Date.UTC(2026, 0, 1)); // 2026-01-01

exports.handler = async () => {
  try {
    const privateKey = process.env.VLTR_BETA_PRIVATE_KEY;
    if (!privateKey) {
      return {
        statusCode: 500,
        body: 'Server configuration error: Private key not found.',
      };
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

    const signature = signer.sign(privateKey).toString('hex');

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

