/**
 * Welcome to Cloudflare Workers!
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */
import { randomUUID, randomBytes, createHmac, createHash } from 'node:crypto';

const ROLE_USER = 0;
const ROLE_ADMIN = 1000;

const DEFAULT_POST_INTERVAL = '60000';

// url_to_pathname('http://example.com/app/path/TO/?q=1', 'http://example.com/app') => '/path/to/index.html', lowercase, ends with /index.html
function url_to_pathname(theUrl, urlPrefix) {
	if (!theUrl.toLowerCase().startsWith(urlPrefix.toLowerCase())) {
		throw { error: 'INVALID_URL', message: 'bad url prefix.' };
	}
	const s = theUrl.substring(urlPrefix.length);
	// only extract pathname:
	const url = new URL('http://localhost:80' + s);
	let pathname = url.pathname.toLowerCase();
	if (pathname.endsWith('/')) {
		pathname = pathname + 'index.html';
	}
	return pathname;
}

// hash('any string') => 32-bytes hex string (can be used as uuid)
function hash(str) {
	const sha1 = createHash('sha1');
	sha1.update(str);
	return sha1.digest('hex').substring(0, 32);
}

// 16-bytes random string:
function randomStr() {
	return randomUUID().substring(19).replace(/-/g, '');
}

// nextId(millis) => 24-bytes uuid starts with time (can be used as increment uuid)
function nextId(ts) {
	// 11 chars until 2500-01-01 => 'f3625217400'
	const sts = ts.toString(16);
	return sts + randomUUID().substring(22).replace(/-/g, '');
}

async function sql_query_first(env, sql, ...args) {
	console.log(`[sql-query-first] ${sql}, args=${args}`);
	return await env.DB.prepare(sql).bind(...args).first();
}

async function sql_query_all(env, sql, ...args) {
	console.log(`[sql-query-all] ${sql}, args=${args}`);
	const { results } = await env.DB.prepare(sql).bind(...args).all();
	return results;
}

async function sql_execute(env, sql, ...args) {
	console.log(`[sql-execute] ${sql}, args=${args}`);
	const { success } = await env.DB.prepare(sql).bind(...args).run();
	if (!success) {
		throw { error: 'SQL_FAILED', message: 'execute sql failed' };
	}
}

async function sql_insert(env, table, obj) {
	const keys = Object.keys(obj);
	const placeholders = keys.map(key => '?');
	const values = keys.map(key => obj[key]);
	const sql = `INSERT INTO ${table} (${keys}) VALUES (${placeholders})`;
	await sql_execute(env, sql, ...values);
}

async function sql_update(env, table, obj, ...keys) {
	const sets = keys.map(key => key + '=?');
	const values = keys.map(key => obj[key]);
	values.push(obj.id);
	const sql = `UPDATE ${table} SET ${sets} WHERE id=?`;
	await sql_execute(env, sql, ...values);
}

async function load_comments(env, pageId, limit = 20) {
	let comments;
	if (pageId) {
		comments = await sql_query_all(env, 'SELECT * FROM comments WHERE page_id = ? ORDER BY updated_at DESC LIMIT ?', pageId, limit);
		for (let comment of comments) {
			if (comment.replies_count === 0) {
				comment.replies = [];
			} else {
				comment.replies = await sql_query_all(env, 'SELECT * FROM replies WHERE comment_id = ? ORDER BY id LIMIT ?', comment.id, limit);
			}
		}
	} else {
		comments = await sql_query_all(env, 'SELECT * FROM comments ORDER BY updated_at DESC LIMIT ?', limit);
		for (let comment of comments) {
			comment.page = await sql_query_first(env, 'SELECT * FROM pages WHERE id = ?', comment.page_id);
		}
	}
	return comments;
}

// validate page and return page object:
async function validate_page(env, pageId, pageUrl, pathname, now) {
	let page = await sql_query_first(env, 'SELECT * FROM pages WHERE id=?', pageId);
	if (page === null || (now - page.updated_at) > 604800_000) {
		// check page url:
		console.log(`check if page url accessible: ${pageUrl}`);
		let resp = await fetch(pageUrl);
		if (resp.status !== 200) {
			throw { error: 'INVALID_URL', message: 'Cannot access page.' };
		}
		// page url ok:
		if (page === null) {
			page = {
				id: pageId,
				pathname: pathname,
				updated_at: now
			}
			await sql_insert(env, 'pages', page);
		} else {
			page.updated_at = now;
			await sql_update(env, 'pages', page, 'updated_at');
		}
		return page;
	}
	// page exist and checked recently:
	return page;
}

// insert comment and return:
async function insert_comment(env, user, pageId, content, now) {
	let commentId = nextId(now);
	let comment = {
		id: commentId,
		page_id: pageId,
		user_id: user.id,
		user_name: user.name,
		user_image: user.image,
		content: content,
		replies_count: 0,
		created_at: now,
		updated_at: now
	};
	user.updated_at = now;
	await sql_update(env, 'users', user, 'updated_at');
	await sql_insert(env, 'comments', comment);
	return comment;
}

// insert reply and return:
async function insert_reply(env, user, commentId, content, now) {
	let replyId = nextId(now);
	let reply = {
		id: replyId,
		comment_id: commentId,
		user_id: user.id,
		user_name: user.name,
		user_image: user.image,
		content: content,
		created_at: now
	};
	user.updated_at = now;
	await sql_update(env, 'users', user, 'updated_at');
	await sql_insert(env, 'replies', reply);
	await update_comment_replies(env, commentId, now, 1);
	return reply;
}

async function update_comment_replies(env, commentId, now, add) {
	if (add > 0) {
		await sql_execute(env, 'UPDATE comments SET replies_count = replies_count + ?, updated_at=? WHERE id=?', add, now, commentId);
	} else {
		await sql_execute(env, 'UPDATE comments SET replies_count = replies_count + ? WHERE id=?', add, commentId);
	}
}

function create_state(salt) {
	const exp = (Date.now() + 600_000).toString(16);
	const rnd = randomBytes(5).toString('hex');
	const payload = `${exp}_${rnd}`;
	const hmac = createHmac('sha1', salt);
	hmac.update(payload);
	const hash = hmac.digest('hex').substring(0, 10);
	return `${payload}_${hash}`;
}

function is_valid_state(state, salt) {
	const [exp, rnd, hash] = state.split('_');
	if (parseInt(exp, 16) < Date.now()) {
		return false;
	}
	const payload = `${exp}_${rnd}`;
	const hmac = createHmac('sha1', salt);
	hmac.update(payload);
	return hash === hmac.digest('hex').substring(0, 10);
}

function create_user_token(user, expires, salt) {
	// id, role, name, image, expires, hash:
	const payload = user.id + '\n' + user.role + '\n' + user.name + '\n' + user.image + '\n' + expires;
	const hmac = createHmac('sha1', salt);
	hmac.update(payload);
	const hash = hmac.digest('hex').substring(0, 10);
	return encodeURIComponent(payload + '\n' + hash)
}

async function parse_user_from_token(env, str) {
	const [id, role, name, image, expires, hash] = decodeURIComponent(str).split('\n');
	if (parseInt(expires) < Date.now()) {
		return null;
	}
	// fetch user salt:
	const db_user = await sql_query_first(env, 'SELECT * FROM users WHERE id = ?', id);
	if (db_user === null) {
		return null;
	}
	const payload = id + '\n' + role + '\n' + name + '\n' + image + '\n' + expires;
	const hmac = createHmac('sha1', db_user.salt);
	hmac.update(payload);
	if (hash !== hmac.digest('hex').substring(0, 10)) {
		return null;
	}
	return db_user;
}

function get_oauth_redirect(provider, state, clientId, redirectUri) {
	switch (provider) {
		case 'github':
			return `https://github.com/login/oauth/authorize?response_type=code&client_id=${clientId}&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;
		case 'qq':
			return `https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=${clientId}&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;
		case 'weibo':
			return `https://api.weibo.com/oauth2/authorize?response_type=code&client_id=${clientId}&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;
		default:
			throw { error: 'INVALID_OAUTH_PROVIDER', data: provider, message: `unsupported oauth provider.` };
	}
}

function oauth_request(env) {
	const salt = env.SALT;
	const provider = env.OAUTH_PROVIDER;
	const clientId = env.OAUTH_CLIENT_ID;
	const redirectUri = env.OAUTH_REDIRECT_URI;
	const state = create_state(salt);
	return Response.redirect(get_oauth_redirect(provider, state, clientId, redirectUri), 302);
}

async function oauth_response(request, env) {
	const now = Date.now();
	const salt = env.SALT;
	const provider = env.OAUTH_PROVIDER;
	const clientId = env.OAUTH_CLIENT_ID;
	const clientSecret = env.OAUTH_CLIENT_SECRET;
	const redirectUri = env.OAUTH_REDIRECT_URI;

	const url = new URL(request.url);
	const state = url.searchParams.get('state');
	const code = url.searchParams.get('code');
	if (!state) {
		return oauth_response_failed('OAuth login failed: missing state.');
	}
	if (!code) {
		return oauth_response_failed('OAuth login failed: missing code.');
	}
	if (!is_valid_state(state, salt)) {
		return oauth_response_failed('OAuth login failed: invalid state.');
	}
	let user = {};
	switch (provider) {
		case 'qq':
			const qqUrl1 = `https://graph.qq.com/oauth2.0/token?fmt=json&grant_type=authorization_code&code=${code}&client_id=${clientId}&client_secret=${clientSecret}&redirect_uri=${encodeURIComponent(redirectUri)}`;
			const qqResp1 = await fetch(qqUrl1);
			const qqJson1 = await qqResp1.json();
			const qqAccessToken = qqJson1.access_token || '';
			if (!qqAccessToken) {
				return oauth_response_failed('OAuth login failed: no access token.');
			}
			const qqUrl2 = `https://graph.qq.com/oauth2.0/me?fmt=json&access_token=${qqAccessToken}`;
			const qqResp2 = await fetch(qqUrl2);
			const qqJson2 = await qqResp2.json();
			const qqOpenId = qqJson2.openid || '';
			if (!qqOpenId) {
				return oauth_response_failed('OAuth login failed: no open id.');
			}
			const qqUrl3 = `https://graph.qq.com/user/get_user_info?oauth_comsumer_key=${clientId}&appid=${clientId}&access_token=${qqAccessToken}&openid=${qqOpenId}`;
			const qqResp3 = await fetch(qqUrl3);
			const qqJson3 = await qqResp3.json();
			// set user profile:
			user.id = qqOpenId;
			user.name = qqJson3.nickname;
			user.image = qqJson3.figureurl_qq_2 || qqJson3.figureurl_qq_1 || qqJson3.figureurl_1 || qqJson3.figureurl;
			break;
		default:
			return oauth_response_failed('OAuth login failed: unsupported oauth provider.');
	}
	// check user:
	if (!user.id) {
		return oauth_response_failed('OAuth login failed: missing user id.');
	}
	if (!user.name) {
		return oauth_response_failed('OAuth login failed: missing user name.');
	}
	if (!user.image) {
		return oauth_response_failed('OAuth login failed: missing user image.');
	}
	// create or update db user:
	let db_user = await sql_query_first(env, 'SELECT * FROM users WHERE id=?', user.id);
	if (db_user === null) {
		// insert:
		db_user = {
			id: user.id,
			role: ROLE_USER,
			name: user.name,
			image: user.image,
			salt: randomStr(),
			locked_at: 0,
			updated_at: 0
		};
		await sql_insert(env, 'users', db_user);
	} else {
		if (db_user.locked_at > now) {
			return oauth_response_failed('User is locked.');
		}
		// update:
		db_user.name = user.name;
		db_user.image = user.image;
		db_user.salt = randomStr();
		await sql_update(env, 'users', db_user, 'name', 'image', 'salt');
	}
	user.role = db_user.role;
	const expires = now + 31536000_000;
	const token = create_user_token(user, expires, db_user.salt);
	const html = `<!DOCTYPE html>
<html>
<head>
<script>
setTimeout(() => {
	console.log('post message to opener...');
	window.opener.postMessage({
		type: 'oauth',
		success: true,
		token: '${token}',
		user: ${JSON.stringify(user)},
		expires: ${expires}
	}, '*');
}, 1000);
</script>
</head>
<body>
	<p>${user.name} signed successfully.</p>
</body>
</html>
`;
	return new Response(html, {
		headers: {
			'Content-Type': 'text/html;charset=utf-8'
		}
	});
}

function oauth_response_failed(error) {
	return create_html_response(`<!DOCTYPE html>
<html>
<head>
</head>
<body>
	<h1>Login failed</h1>
	<p>${error}</p>
</body>
</html>
`);
}

function create_html_response(html) {
	return new Response(html, {
		headers: {
			'Content-Type': 'text/html;charset=utf-8'
		}
	});
}

// user from auth header, or null if parse failed:
async function get_user_from_auth_header(request, env) {
	const auth = request.headers.get('Authorization');
	if (auth && auth.startsWith('Bearer: ')) {
		const token = auth.substring(8).trim();
		return await parse_user_from_token(env, token);
	}
	return null;
}

async function get_comments(request, url, env) {
	const pageUrl = url.searchParams.get('url') || '';
	console.log(pageUrl);
	let result;
	if (!pageUrl) {
		// no page url, return recent comments:
		const size = parseInt(url.searchParams.get('size') || 20);
		const comments = await load_comments(env, '', size);
		result = JSON.stringify({
			comments: comments
		});
	} else {
		// by page url:
		const pathname = url_to_pathname(pageUrl, env.PAGE_ORIGIN + (env.PAGE_PATH_PREFIX || ''));
		const pageId = hash(pathname);
		result = await env.KV.get(pageId);
		if (!result) {
			const comments = await load_comments(env, pageId);
			result = JSON.stringify({
				comments: comments
			});
			if (comments.length > 0) {
				await env.KV.put(pageId, result);
			}
		}
	}
	// NOTE result is a json string:
	return new Response(result, {
		headers: {
			'Content-Type': 'application/json'
		}
	});
}

async function check_user(request, env, now, checkRateLimit = true) {
	const db_user = await get_user_from_auth_header(request, env);
	if (db_user === null) {
		throw { error: 'SIGNIN_REQUIRED', message: 'Please signin first.' };
	}
	if (db_user.locked_at > now) {
		throw { error: 'USER_LOCKED', message: 'User is locked.' };
	}
	if (checkRateLimit && db_user.role === ROLE_USER && ((now - db_user.updated_at) < (parseInt(env.POST_INTERVAL || DEFAULT_POST_INTERVAL)))) {
		throw { error: 'RATE_LIMIT', message: 'Please wait a little while.' };
	}
	return db_user;
}

async function post_reply(request, env) {
	const now = Date.now();
	const user = await check_user(request, env, now);
	// make a reply:
	const body = await request.json();
	// check commentId:
	const commentId = body.commentId || '';
	if (!commentId) {
		throw { error: 'INVALID_PARAMETER', data: 'commentId', message: 'Missing commentId.' };
	}
	const content = (body.content || '').trim();
	if (!content) {
		throw { error: 'INVALID_PARAMETER', date: 'content', message: 'Missing content.' };
	}
	// reply:
	const comment = await sql_query_first(env, 'SELECT id, page_id, replies_count FROM comments WHERE id=?', commentId);
	if (!comment) {
		throw { error: 'INVALID_PARAMETER', data: 'commentId', message: 'Invalid commentId.' };
	}
	const reply = await insert_reply(env, user, commentId, content, now);
	if (comment.replies_count <= 20) {
		// clear cache:
		await env.KV.delete(comment.page_id);
	}
	return Response.json(reply);
}

async function delete_reply(request, env) {
	const now = Date.now();
	const user = await check_user(request, env, now, false);
	const body = await request.json();
	const replyId = body.replyId || '';
	if (!replyId) {
		throw { error: 'INVALID_PARAMETER', data: 'replyId', message: 'Missing replyId.' };
	}
	const reply = await sql_query_first(env, 'SELECT * FROM replies WHERE id = ?', replyId);
	if (reply === null) {
		throw { error: 'INVALID_PARAMETER', data: 'replyId', message: 'Reply not exist.' };
	}
	if (user.role !== ROLE_ADMIN && user.id !== reply.user_id) {
		throw { error: 'PERMISSION_DENIED', message: 'Cannot delete reply.' };
	}
	const comment = await sql_query_first(env, 'SELECT page_id FROM comments WHERE id = ?', reply.comment_id);
	// delete reply:
	await sql_execute(env, 'DELETE FROM replies WHERE id = ?', reply.id);
	await update_comment_replies(env, reply.comment_id, now, -1);

	// remove cache:
	await env.KV.delete(comment.page_id);
	return Response.json({
		id: reply.id
	});
}

async function post_comment(request, env) {
	const now = Date.now();
	const user = await check_user(request, env, now);
	const body = await request.json();
	// check pageUrl or commentId:
	const pageUrl = body.pageUrl || '';
	if (!pageUrl) {
		throw { error: 'INVALID_PARAMETER', data: 'pageUrl', message: 'Missing pageUrl.' };
	}
	const content = (body.content || '').trim();
	if (!content) {
		throw { error: 'INVALID_PARAMETER', data: 'content', message: 'Missing content.' };
	}
	if (content.length > 20000) {
		throw { error: 'INVALID_PARAMETER', data: 'content', message: 'Content too long.' };
	}
	// normalize page url:
	const pathname = url_to_pathname(pageUrl, env.PAGE_ORIGIN + (env.PAGE_PATH_PREFIX || ''));
	const pageId = hash(pathname);
	await validate_page(env, pageId, pageUrl, pathname, now);
	const comment = await insert_comment(env, user, pageId, content, now);
	// clear cache:
	await env.KV.delete(pageId);
	return Response.json(comment);
}

async function delete_comment(request, env) {
	const now = Date.now();
	const user = await check_user(request, env, now, false);
	const body = await request.json();
	const commentId = body.commentId || '';
	if (!commentId) {
		throw { error: 'INVALID_PARAMETER', data: 'commentId', message: 'Missing commentId.' };
	}
	const comment = await sql_query_first(env, 'SELECT * FROM comments WHERE id = ?', commentId);
	if (comment === null) {
		throw { error: 'INVALID_PARAMETER', data: 'commentId', message: 'Comment not exist.' };
	}
	if (user.role !== ROLE_ADMIN && user.id !== comment.user_id) {
		throw { error: 'PERMISSION_DENIED', message: 'Cannot delete comment.' };
	}
	// delete comment / replies:
	await sql_execute(env, 'DELETE FROM comments WHERE id = ?', comment.id);
	await sql_execute(env, 'DELETE FROM replies WHERE comment_id = ?', comment.id);
	// remove cache:
	await env.KV.delete(comment.page_id);
	return Response.json({
		id: comment.id
	});
}

function oauth_signout() {
	return new Response('{"oauth":"signout"}', {
		headers: {
			'Content-Type': 'application/json',
			'Set-Cookie': 'user=delete; Max-Age=0; Path=/api; HttpOnly'
		}
	});
}

function add_cors(response, env) {
	response.headers.set('Access-Control-Allow-Origin', env.PAGE_ORIGIN);
	response.headers.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, HEAD, OPTIONS');
	response.headers.set('Access-Control-Allow-Headers', '*');
	response.headers.set('Access-Control-Max-Age', '2592000');
	response.headers.set("Vary", "Origin");
}

function translate_error(err, env) {
	if (err.error) {
		err.message = env['I18N_' + err.error] || err.message;
	}
	return err;
}

export default {
	async fetch(request, env, ctx) {
		let url = new URL(request.url);
		console.log(`${new Date()} ${request.method}: ${url} `);
		if (url.protocol === 'http:' && env.ALWAYS_HTTPS === 'true') {
			url.protocol = 'https:';
			return Response.redirect(url.toString, 301);
		}
		let response = null;
		switch (url.pathname) {
			case '/api/comments':
				try {
					switch (request.method) {
						case 'GET':
							response = await get_comments(request, url, env);
							break;
						case 'POST':
							response = await post_comment(request, env);
							break;
						case 'DELETE':
							response = await delete_comment(request, env);
							break;
						case 'OPTIONS':
							response = new Response(null);
							break;
						default:
							throw 'bad method.';
					}
				} catch (err) {
					console.error(err);
					response = Response.json(translate_error(err, env), {
						status: 400
					});
				}
				add_cors(response, env);
				return response;

			case '/api/replies':
				try {
					switch (request.method) {
						case 'POST':
							response = await post_reply(request, env);
							break;
						case 'DELETE':
							response = await delete_reply(request, env);
							break;
						case 'OPTIONS':
							response = new Response(null);
							break;
						default:
							throw 'bad method.';
					}
				} catch (err) {
					console.error(err);
					response = Response.json(translate_error(err, env), {
						status: 400
					});
				}
				add_cors(response, env);
				return response;

			case '/oauth_request':
				return oauth_request(env);
			case '/oauth_response':
				return await oauth_response(request, env);
			case '/oauth_signout':
				return oauth_signout();
			case '/manage':
				break;
		}
		return create_html_response('<html><body><h1>404 Not Found</h1></body></html>');
	},
};
