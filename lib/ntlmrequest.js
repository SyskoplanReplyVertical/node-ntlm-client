'use strict';

const http = require('http');
const https = require('https');
const ntlm = require('./ntlm');


function ntlmRequest(opts) {
	if (
		opts === undefined ||
		!('uri' in opts) ||
		!('method' in opts) ||
		!('username' in opts) ||
		!('password' in opts)
	) {
		throw new Error('Required options missing');
	}

	const baseHeaders = {
		'User-Agent': 'node.js',
		'Accept': '*/*',
		'Connection': 'keep-alive',
	};

	const httpAgent = new http.Agent({ keepAlive: true });
	const httpsAgent = new https.Agent({ keepAlive: true });
	const cookieJar = []; // Simple cookie storage

	function agentFor(url) {
		return url.startsWith('https:') ? httpsAgent : httpAgent;
	}

	function parseAuthSchemes(wwwAuthenticateHeader) {
		if (!wwwAuthenticateHeader) return [];

		const schemes = [];
		const parts = wwwAuthenticateHeader.split(',');
		
		for (const part of parts) {
			const trimmed = part.trim();
			// Extract only scheme name, ignore parameters
			if (!/^[^\s=]+=.+/.test(trimmed)) {
				const schemeName = trimmed.split(/\s+/)[0].toLowerCase();
				if (schemeName) schemes.push(schemeName);
			}
		}
		
		return schemes;
	}

	function extractCookies(response) {
		const setCookie = response.headers.get('set-cookie');
		if (setCookie) {
			cookieJar.push(...setCookie.split(',').map(c => c.split(';')[0].trim()));
		}
	}

	function getCookieHeader() {
		return cookieJar.length > 0 ? cookieJar.join('; ') : undefined;
	}

	async function doFetch(authHeader) {
		const url = new URL(opts.uri);

		const extra = opts.request || {};
		const extraHeaders = (extra.headers || {});

		const headers = {
			...baseHeaders,
			...extraHeaders,
		};

		if (authHeader) {
			headers['Authorization'] = authHeader;
		}

		const cookieHeader = getCookieHeader();
		if (cookieHeader) {
			headers['Cookie'] = cookieHeader;
		}

		const fetchOptions = {
			method: opts.method,
			headers,
			dispatcher: agentFor(url.href), // For undici/node-fetch compatibility
		};

		if (extra.body) {
			fetchOptions.body = extra.body;
		}

		// Merge other options but preserve our headers
		Object.keys(extra).forEach(key => {
			if (key !== 'headers' && key !== 'body') {
				fetchOptions[key] = extra[key];
			}
		});

		const res = await fetch(opts.uri, fetchOptions);
		extractCookies(res);
		const bodyText = await res.text();
		
		return { res, bodyText };
	}

	return (async () => {
		let { res, bodyText } = await doFetch(undefined);

		if (res.status !== 401) {
			return { response: res, body: bodyText };
		}

		const wwwAuth = res.headers.get('www-authenticate') || '';
		const schemes = parseAuthSchemes(wwwAuth);

		if (schemes.includes('ntlm')) {
			// NTLM Type 1
			({ res, bodyText } = await doFetch(ntlm.createType1Message()));

			if (res.status !== 401) {
				return { response: res, body: bodyText };
			}

			// NTLM Type 2
			let type2;
			try {
				type2 = ntlm.decodeType2Message({
					headers: {
						'www-authenticate': res.headers.get('www-authenticate'),
					},
					statusCode: res.status,
				});
			} catch (e) {
				throw new Error('The server didnt respond properly: ' + (e.stack || e.toString()));
			}

			// NTLM Type 3
			const type3 = ntlm.createType3Message(
				type2,
				opts.username,
				opts.password,
				opts.workstation,
				opts.target
			);

			({ res, bodyText } = await doFetch(type3));

		} else if (schemes.includes('basic')) {
			// Basic authentication
			const basic = Buffer.from(`${opts.username}:${opts.password}`).toString('base64');
			({ res, bodyText } = await doFetch(`Basic ${basic}`));
		} else {
			throw new Error('Could not negotiate on an authentication scheme');
		}

		if (res.status < 200 || res.status > 299) {
			throw new Error(`HTTP ${res.status}: ${res.statusText}`);
		}

		return { response: res, body: bodyText };
	})();
}

module.exports = ntlmRequest;
