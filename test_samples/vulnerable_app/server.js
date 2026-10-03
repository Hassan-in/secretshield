const https = require('https');
const crypto = require('crypto');

// Disabling TLS verification (BAD)
const agent = new https.Agent({ rejectUnauthorized: false });

// Hardcoded secret (BAD)
const clientSecret = "9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4938271605f4e3d2c";

function weakHash(input) {
  return crypto.createHash('sha1').update(input).digest('hex');
}

function makeId() {
  return Math.random().toString(36).substring(2);
}

module.exports = { weakHash, makeId, clientSecret };
