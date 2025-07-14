import http from 'http';
import https from 'https';
import { URL } from 'url';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';
import crypto from 'crypto';

class GatewayContext {
  constructor() {
    this.jwksCache = null;
    this.jwksLastUpdate = new Date(0);
  }
}

function base64urlDecode(str) {
  // Add padding if needed
  const padded = str + '='.repeat((4 - str.length % 4) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function getKeyFromJwks(jwksData) {
  return (header, callback) => {
    try {
      const jwks = JSON.parse(jwksData);
      const jwk = jwks.keys.find(key => key.kid === header.kid);
      
      if (!jwk) {
        return callback(new Error(`Unknown kid: ${header.kid}`));
      }
      
      if (jwk.kty !== 'RSA') {
        return callback(new Error('Only RSA keys are supported'));
      }
      
      // Decode n and e from base64url
      const nBuffer = base64urlDecode(jwk.n);
      const eBuffer = base64urlDecode(jwk.e);
      
      // Convert to integers
      const n = BigInt('0x' + nBuffer.toString('hex'));
      const e = parseInt(eBuffer.toString('hex'), 16);
      
      // Create RSA public key
      const publicKey = crypto.createPublicKey({
        key: {
          kty: 'RSA',
          n: jwk.n,
          e: jwk.e
        },
        format: 'jwk'
      });
      
      callback(null, publicKey);
    } catch (error) {
      callback(error);
    }
  };
}

async function validateTokenCameFromGitHub(oidcTokenString, gatewayContext) {
  const now = new Date();
  
  // Check if we need to refresh JWKS cache
  if (now - gatewayContext.jwksLastUpdate > 60000 || !gatewayContext.jwksCache) {
    try {
      const response = await fetch('https://token.actions.githubusercontent.com/.well-known/jwks');
      const jwksData = await response.text();
      gatewayContext.jwksCache = jwksData;
      gatewayContext.jwksLastUpdate = now;
    } catch (error) {
      console.error('Unable to get JWKS configuration:', error);
      throw new Error('Unable to get JWKS configuration');
    }
  }
  
  return new Promise((resolve, reject) => {
    jwt.verify(
      oidcTokenString,
      getKeyFromJwks(gatewayContext.jwksCache),
      { algorithms: ['RS256'] },
      (err, decoded) => {
        if (err) {
          reject(new Error('Unable to validate JWT'));
        } else {
          resolve(decoded);
        }
      }
    );
  });
}

function transfer(destination, source) {
  source.pipe(destination);
  destination.on('close', () => source.destroy());
  source.on('close', () => destination.destroy());
}

function handleProxyRequest(req, res) {
  const url = new URL(`http://${req.url}`);
  const options = {
    host: url.hostname,
    port: url.port || 80,
    timeout: 5000
  };
  
  const proxySocket = http.request(options);
  
  proxySocket.on('connect', (proxyRes, socket) => {
    res.writeHead(200, 'Connection Established');
    transfer(socket, req.socket);
    transfer(req.socket, socket);
  });
  
  proxySocket.on('error', (err) => {
    console.error('Proxy connection error:', err);
    res.writeHead(408, 'Request Timeout');
    res.end();
  });
  
  proxySocket.end();
}

async function handleApiRequest(req, res) {
  try {
    const response = await fetch('https://www.bing.com');
    const body = await response.text();
    res.writeHead(response.status, response.headers.raw());
    res.end(body);
  } catch (error) {
    console.error('API request error:', error);
    res.writeHead(500, 'Internal Server Error');
    res.end();
  }
}

async function requestHandler(req, res) {
  const gatewayContext = req.gatewayContext;
  
  // Only handle CONNECT method and /apiExample path
  if (req.method !== 'CONNECT' && req.url !== '/apiExample') {
    res.writeHead(404, 'Not Found');
    res.end();
    return;
  }
  
  // Check that the OIDC token verifies as a valid token from GitHub
  const oidcTokenString = req.headers['gateway-authorization'];
  
  if (!oidcTokenString) {
    res.writeHead(401, 'Unauthorized');
    res.end();
    return;
  }
  
  try {
    const claims = await validateTokenCameFromGitHub(oidcTokenString, gatewayContext);
    
    // Token is valid, but we must check some claim specific to our use case
    if (claims.repository !== 'octo-org/octo-repo') {
      res.writeHead(401, 'Unauthorized');
      res.end();
      return;
    }
    
    // Check custom audience
    if (claims.aud !== 'api://ActionsOIDCGateway') {
      res.writeHead(401, 'Unauthorized');
      res.end();
      return;
    }
    
    // Now that claims have been verified, we can service the request
    if (req.method === 'CONNECT') {
      handleProxyRequest(req, res);
    } else if (req.url === '/apiExample') {
      await handleApiRequest(req, res);
    }
    
  } catch (error) {
    console.error('Token validation error:', error);
    res.writeHead(401, 'Unauthorized');
    res.end();
  }
}

function main() {
  console.log('starting up');
  
  const gatewayContext = new GatewayContext();
  
  const server = http.createServer((req, res) => {
    req.gatewayContext = gatewayContext;
    requestHandler(req, res);
  });
  
  server.setTimeout(60000);
  server.listen(8000, () => {
    console.log('Server listening on port 8000');
  });
}

// Only run main if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { 
  GatewayContext, 
  getKeyFromJwks, 
  validateTokenCameFromGitHub, 
  base64urlDecode,
  requestHandler 
};