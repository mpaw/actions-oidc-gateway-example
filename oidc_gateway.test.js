import { jest } from '@jest/globals';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { 
  GatewayContext, 
  getKeyFromJwks, 
  validateTokenCameFromGitHub, 
  base64urlDecode 
} from './oidc_gateway.js';

function generateTestKeyPair() {
  // Generate key pair with PEM format
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  
  // Convert public key to JWK format manually
  const keyObject = crypto.createPublicKey(publicKey);
  const jwk = keyObject.export({ format: 'jwk' });
  
  return { publicKey, privateKey, jwk };
}

describe('OIDC Gateway', () => {
  describe('base64urlDecode', () => {
    test('should decode base64url strings correctly', () => {
      const input = 'AQAB';
      const result = base64urlDecode(input);
      expect(result).toBeInstanceOf(Buffer);
    });
  });

  describe('getKeyFromJwks', () => {
    test('should extract RSA public key from JWKS', (done) => {
      const { jwk } = generateTestKeyPair();

      const jwks = {
        keys: [{
          kty: 'RSA',
          kid: 'testKey',
          alg: 'RS256',
          use: 'sig',
          n: jwk.n,
          e: jwk.e
        }]
      };

      const getKeyFunc = getKeyFromJwks(JSON.stringify(jwks));
      const header = { kid: 'testKey', alg: 'RS256' };

      getKeyFunc(header, (err, key) => {
        expect(err).toBeNull();
        expect(key).toBeDefined();
        done();
      });
    });

    test('should fail with unknown key ID', (done) => {
      const jwks = { keys: [] };
      const getKeyFunc = getKeyFromJwks(JSON.stringify(jwks));
      const header = { kid: 'unknownKey', alg: 'RS256' };

      getKeyFunc(header, (err, key) => {
        expect(err).toBeDefined();
        expect(err.message).toContain('Unknown kid');
        done();
      });
    });
  });

  describe('validateTokenCameFromGitHub', () => {
    let gatewayContext;
    let keyPair;

    beforeEach(() => {
      gatewayContext = new GatewayContext();
      keyPair = generateTestKeyPair();
    });

    test('should validate token signed with correct key', async () => {
      const jwks = {
        keys: [{
          kty: 'RSA',
          kid: 'testKey',
          alg: 'RS256',
          use: 'sig',
          n: keyPair.jwk.n,
          e: keyPair.jwk.e
        }]
      };

      // Mock JWKS cache (simulating recent fetch)
      gatewayContext.jwksCache = JSON.stringify(jwks);
      gatewayContext.jwksLastUpdate = new Date();

      const payload = { for: 'testing' };
      const token = jwt.sign(payload, keyPair.privateKey, { 
        algorithm: 'RS256', 
        keyid: 'testKey' 
      });

      const claims = await validateTokenCameFromGitHub(token, gatewayContext);
      expect(claims.for).toBe('testing');
    });

    test('should reject token signed with wrong key', async () => {
      const wrongKeyPair = generateTestKeyPair();

      const jwks = {
        keys: [{
          kty: 'RSA',
          kid: 'testKey',
          alg: 'RS256',
          use: 'sig',
          n: keyPair.jwk.n,
          e: keyPair.jwk.e
        }]
      };

      gatewayContext.jwksCache = JSON.stringify(jwks);
      gatewayContext.jwksLastUpdate = new Date();

      const payload = { for: 'testing' };
      const token = jwt.sign(payload, wrongKeyPair.privateKey, { 
        algorithm: 'RS256', 
        keyid: 'testKey' 
      });

      await expect(validateTokenCameFromGitHub(token, gatewayContext))
        .rejects.toThrow('Unable to validate JWT');
    });

    test('should reject unsigned token', async () => {
      const jwks = {
        keys: [{
          kty: 'RSA',
          kid: 'testKey',
          alg: 'RS256',
          use: 'sig',
          n: keyPair.jwk.n,
          e: keyPair.jwk.e
        }]
      };

      gatewayContext.jwksCache = JSON.stringify(jwks);
      gatewayContext.jwksLastUpdate = new Date();

      // Create an invalid token
      const invalidToken = 'invalid.token.here';

      await expect(validateTokenCameFromGitHub(invalidToken, gatewayContext))
        .rejects.toThrow('Unable to validate JWT');
    });
  });
});