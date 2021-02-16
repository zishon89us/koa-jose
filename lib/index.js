'use strict';

const unless = require('koa-unless');
const { default: ParseJwk } = require('jose/jwk/parse')
const { default: JwtVerify } = require('jose/jwt/verify')
const { default: CompactDecrypt } = require('jose/jwe/compact/decrypt')

const decode = TextDecoder.prototype.decode.bind(new TextDecoder());

const resolveAuthHeader = require('./resolvers/auth-header');

module.exports = (opts = {}) => {
		const { token, privateJwk, alg_1 = 'RSA-OAEP-256', issuerPublicJwk, alg_2 = 'ES256', isRevoked, key = 'user', passthrough, debug} = opts;
    const tokenResolvers = [resolveAuthHeader];

    const middleware = async function jwt(ctx, next) {
        let token;
        tokenResolvers.find(resolver => token = resolver(ctx, opts));

        if (!token && !passthrough) {
            ctx.throw(401, debug ? 'Token not found' : 'Authentication Error');
        }

        try {
            if (!privateJwk || !issuerPublicJwk) {
                throw new Error('keys not provided');
            }

						// TODO: decode and decrypt token here	
						const privateKey = await parseJwk(privateJwk, alg_1);
						let { plaintext: decryptedJwt } = await CompactDecrypt(token, privateKey);
						const publicKey = await parseJwk(issuerPublicJwk, alg_2);
						const { protectedHeader, payload } = await JwtVerify(decode(decryptedJwt), publicKey);
						const decodedToken = payload; 
		
						// TODO: fix this later			
            if (isRevoked) {
                const tokenRevoked = await isRevoked(ctx, decodedToken, token);
                if (tokenRevoked) {
                    throw new Error('Token revoked');
                }
            }

            ctx.state[key] = decodedToken;
            if (tokenKey) {
                ctx.state[tokenKey] = token;
            }

        } catch (e) {
            if (!passthrough) {
                const msg = debug ? e.message : 'Authentication Error';
                ctx.throw(401, msg, { originalError: e });
            }else{ 
                //lets downstream middlewares handle JWT exceptions
                ctx.state.jwtOriginalError = e;
            }
        }

        return next();
    };

    middleware.unless = unless;
    return middleware;
};
