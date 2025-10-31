import crypto from 'crypto';

const EXPIRATION_DATE = new Date(Date.UTC(2026, 0, 1));

export default async function handler(req, res) {
  try {
    let privateKey = process.env.VLTR_BETA_PRIVATE_KEY;
    if (!privateKey) {
      return res.status(500).send('Server configuration error: Private key not found.');
    }

    if (privateKey.includes('\\n')) {
      privateKey = privateKey.replace(/\\n/g, '\n');
    }

    privateKey = privateKey.replace(/\r\n?/g, '\n').trim();

    if (!privateKey.includes('BEGIN') || !privateKey.includes('END')) {
      return res.status(500).send('Server configuration error: Invalid private key format.');
    }

    if (!privateKey.endsWith('\n')) {
      privateKey += '\n';
    }

    const payload = {
      issue_date: new Date().toISOString(),
      expiration_date: EXPIRATION_DATE.toISOString(),
      issuer: 'VLTR Beta Program',
    };

    const signer = crypto.createSign('sha256');
    signer.update(JSON.stringify(payload));
    signer.end();

    const keyOptions = privateKey.includes('BEGIN EC PRIVATE KEY')
      ? { key: privateKey, format: 'pem', type: 'sec1' }
      : { key: privateKey, format: 'pem', type: 'pkcs8' };

    const keyObject = crypto.createPrivateKey(keyOptions);
    const signature = signer.sign({ key: keyObject, dsaEncoding: 'der' }).toString('hex');

    res.status(200).json({ payload, signature });
  } catch (err) {
    res.status(500).send(`An error occurred: ${err.message}`);
  }
}

