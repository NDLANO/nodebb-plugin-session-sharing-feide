'use strict';

const winston = module.parent.require('winston');
const nconf = module.parent.require('nconf');

const util = require('util');

const _ = require('lodash');
const jwt = require('jsonwebtoken');

const meta = require.main.require('./src/meta');
const user = require.main.require('./src/user');
const groups = require.main.require('./src/groups');
const SocketPlugins = require.main.require('./src/socket.io/plugins');
const db = require.main.require('./src/database');
const plugins = require.main.require('./src/plugins');

const controllers = require('./lib/controllers');
const nbbAuthController = require.main.require('./src/controllers/authentication');
const logoutAsync = util.promisify((req, callback) => req.logout(callback));

/* all the user profile fields that can be passed to user.updateProfile */
const profileFields = [
	'username',
	'email',
	'fullname',
	'website',
	'location',
	'groupTitle',
	'birthday',
	'signature',
	'aboutme',
];
const payloadKeys = profileFields.concat([
	'sub', // the uniq identifier of that account
	'firstName', // for backwards compatibillity
	'lastName', // dto.
	'picture',
	'groups',
]);

const plugin = {
	ready: false,
	settings: {
		name: 'appId',
		headerName: 'authorization',
		cookieDomain: undefined,
		secret: '',
		behaviour: 'trust',
		adminRevalidate: 'off',
		noRegistration: 'off',
		payloadParent: undefined,
		allowBannedUsers: false,
	},
};

payloadKeys.forEach(function (key) {
	plugin.settings['payload:' + key] = key;
});

plugin.init = async (params) => {
	var router = params.router;
	var hostMiddleware = params.middleware;

	router.get('/admin/plugins/session-sharing', hostMiddleware.admin.buildHeader, controllers.renderAdminPage);
	router.get('/api/admin/plugins/session-sharing', controllers.renderAdminPage);

	router.get('/api/session-sharing/lookup', controllers.retrieveUser);
	router.post('/api/session-sharing/user', controllers.process);

	if (process.env.NODE_ENV === 'development') {
		router.get('/debug/session', plugin.generate);
	}

	await plugin.reloadSettings();
};

plugin.appendConfig = async (config) => {
	config.sessionSharing = {
		logoutRedirect: plugin.settings.logoutRedirect,
		loginOverride: plugin.settings.loginOverride,
		registerOverride: plugin.settings.registerOverride,
		editOverride: plugin.settings.editOverride,
		hostWhitelist: plugin.settings.hostWhitelist,
	};

	return config;
};

/* Websocket Listeners */

SocketPlugins.sessionSharing = {};

SocketPlugins.sessionSharing.showUserIds = async (socket, data) => {
	// Retrieve the hash and find matches
	const { uids } = data;

	if (!uids.length) {
		throw new Error('no-uids-supplied');
	}

	return Promise.all(uids.map(async uid => db.getSortedSetRangeByScore(plugin.settings.name + ':uid', 0, -1, uid, uid)));
};

SocketPlugins.sessionSharing.findUserByRemoteId = async (socket, data) => {
	if (!data.remoteId) {
		throw new Error('no-remote-id-supplied');
	}

	return plugin.getUser(data.remoteId);
};

/* End Websocket Listeners */

/*
 *	Given a remoteId, show user data
 */
plugin.getUser = async (remoteId) => {
	const uid = await db.sortedSetScore(plugin.settings.name + ':uid', remoteId);

	if (!uid) {
		return;
	}

	return user.getUserFields(uid, ['username', 'userslug', 'picture']);
};

plugin.process = async (token) => {
	const userData = await this.validateToken(token);
	const [uid, isNewUser] = await plugin.findOrCreateUser(userData);
	await plugin.updateUserProfile(uid, userData, isNewUser);
	await plugin.updateUserGroups(uid, userData);
	await plugin.verifyUser(token, uid, isNewUser);
	return uid;
};

plugin.verifyUser = async (token, uid, isNewUser) => {
	await plugins.hooks.fire('static:sessionSharing.verifyUser', {
		uid: uid,
		isNewUser: isNewUser,
		token: token,
	});

	// Check ban state of user
	const isBanned = await user.bans.isBanned(uid);

	// Reject if banned and settings dont allow banned users to login
	if (isBanned && !plugin.settings.allowBannedUsers) {
		throw new Error('banned');
	}
};

plugin.findOrCreateUser = async (userData) => {
	const { id } = userData;
	let isNewUser = false;
	let userId = null;
	let queries = [db.sortedSetScore(plugin.settings.name + ':uid', userData.id)];

	if (userData.email && userData.email.length) {
		queries = [...queries, db.sortedSetScore('email:uid', userData.email)];
	}

	let [uid, mergeUid] = await Promise.all(queries);
	uid = parseInt(uid, 10);
	mergeUid = parseInt(mergeUid, 10);

	/* check if found something to work with */
	if (uid && !isNaN(uid)) {
		try {
			/* check if the user with the given id actually exists */
			const exists = await user.exists(uid);

			if (exists) {
				userId = uid;
			} else {
				/* reference is outdated, user got deleted */
				await db.sortedSetRemove(plugin.settings.name + ':uid', id);
			}
		} catch (error) {
			/* ignore errors, but assume the user doesn't exist  */
			winston.warn('[session-sharing] Error while testing user existance', error);
		}
	}

	if (!userId && mergeUid && !isNaN(mergeUid)) {
		winston.info('[session-sharing] Found user via their email, associating this id (' + id + ') with their NodeBB account');
		await db.sortedSetAdd(plugin.settings.name + ':uid', mergeUid, id);
		userId = mergeUid;
	}

	/* create the user from payload if necessary */
	winston.debug('createUser?', !userId);
	if (!userId) {
		if (plugin.settings.noRegistration === 'on') {
			throw new Error('no-match');
		}

		userId = await plugin.createUser(userData);
		isNewUser = true;
	}

	return [userId, isNewUser];
};

plugin.updateUserProfile = async (uid, userData, isNewUser) => {
	winston.debug('consider updateProfile?', isNewUser || plugin.settings.updateProfile === 'on');
	let userObj = {};

	/* even update the profile on a new account, since some fields are not initialized by NodeBB */
	if (!isNewUser && plugin.settings.updateProfile !== 'on') {
		return;
	}

	const existingFields = await user.getUserFields(uid, profileFields);
	const obj = profileFields.reduce((result, field) => {
		if (typeof userData[field] !== 'undefined' && existingFields[field] !== userData[field]) {
			result[field] = userData[field];
		}

		return result;
	}, {});

	if (Object.keys(obj).length) {
		winston.debug('[session-sharing] Updating profile fields:', obj);
		obj.uid = uid;
		try {
			userObj = await user.updateProfile(uid, obj);

			// If it errors out, not that big of a deal, continue anyway.
			if (!userObj) {
				userObj = existingFields;
			}
		} catch (error) {
			winston.warn('[session-sharing] Unable to update profile information for uid: ' + uid + '(' + error.message + ')');
		}
	}

	if (userData.picture) {
		await db.setObjectField('user:' + uid, 'picture', userData.picture);
	}
};

plugin.updateUserGroups = async (uid, userData) => {
	if (!userData.groups || !Array.isArray(userData.groups)) {
		return;
	}

	// Retrieve user groups
	let [userGroups] = await groups.getUserGroupsFromSet('groups:createtime', [uid]);
	// Normalize user group data to just group names
	userGroups = userGroups.map(groupObj => groupObj.name);

	// Build join and leave arrays
	let join = userData.groups.filter(name => !userGroups.includes(name));
	if (plugin.settings.syncGroupList === 'on') {
		join = join.filter(group => plugin.settings.syncGroups.includes(group));
	}

	let leave = userGroups.filter((name) => {
		// `registered-users` is always a joined group
		if (name === 'registered-users') {
			return false;
		}

		return !userData.groups.includes(name);
	});
	if (plugin.settings.syncGroupList === 'on') {
		leave = leave.filter(group => plugin.settings.syncGroups.includes(group));
	}

	await executeJoinLeave(uid, join, leave);
};

async function executeJoinLeave(uid, join, leave) {
	await Promise.all([
		(async () => {
			if (plugin.settings.syncGroupJoin !== 'on') {
				return;
			}

			await Promise.all(join.map(name => groups.join(name, uid)));
		})(),
		(async () => {
			if (plugin.settings.syncGroupLeave !== 'on') {
				return;
			}

			await Promise.all(leave.map(name => groups.leave(name, uid)));
		})(),
	]);
}

plugin.createUser = async (userData) => {
	winston.verbose('[session-sharing] No user found, creating a new user for this login');

	const uid = await user.create(_.pick(userData, profileFields));
	await db.sortedSetAdd(plugin.settings.name + ':uid', uid, userData.id);
	return uid;
};

plugin.addMiddleware = async function ({ req, res }) {
	console.log(req, res)
	winston.verbose('[session-sharing] test rebuild');
	const { hostWhitelist, guestRedirect, editOverride, loginOverride, registerOverride } = await meta.settings.get('session-sharing');

	if (hostWhitelist) {
		const hosts = hostWhitelist.split(',') || [hostWhitelist];
		let whitelisted = false;
		for (const host of hosts) {
			if (req.headers.host.includes(host)) {
				whitelisted = true;
				break;
			}
		}

		if (!whitelisted) {
			return;
		}
	}

	function handleGuest(req, res) {
		if (guestRedirect && !req.originalUrl.startsWith(nconf.get('relative_path') + '/login?local=1')) {
			// If a guest redirect is specified, follow it
			res.redirect(guestRedirect.replace('%1', encodeURIComponent(req.protocol + '://' + req.get('host') + req.originalUrl)));
		} else if (res.locals.fullRefresh === true) {
			res.redirect(nconf.get('relative_path') + req.url);
		}
	}

	// Only respond to page loads by guests, not api or asset calls
	const hasSession = req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && parseInt(req.user.uid, 10) > 0;
	const hasLoginLock = req.session.hasOwnProperty('loginLock');

	if (
		!plugin.ready ||	// plugin not ready
		(plugin.settings.behaviour === 'trust' && hasSession) ||	// user logged in + "trust" behaviour
		((plugin.settings.behaviour === 'revalidate' || plugin.settings.behaviour === 'update') && hasLoginLock) ||
		req.originalUrl.startsWith(nconf.get('relative_path') + '/api')	// api routes
	) {
		// Let requests through under "update" or "revalidate" behaviour only if they're logging in for the first time
		delete req.session.loginLock;	// remove login lock for "update" or "revalidate" logins

		return;
	}

	if (editOverride && hasSession && req.originalUrl.match(/\/user\/.*\/edit(\/\w+)?$/)) {
		return res.redirect(editOverride.replace('%1', encodeURIComponent(req.protocol + '://' + req.get('host') + req.originalUrl)));
	}
	if (loginOverride && req.originalUrl.match(/\/login$/)) {
		return res.redirect(loginOverride.replace('%1', encodeURIComponent(req.protocol + '://' + req.get('host') + req.originalUrl)));
	}
	if (registerOverride && req.originalUrl.match(/\/register$/)) {
		return res.redirect(registerOverride.replace('%1', encodeURIComponent(req.protocol + '://' + req.get('host') + req.originalUrl)));
	}

	// Hook into ip blacklist functionality in core
	try {
		await meta.blacklist.test(req.ip);
	} catch (error) {
		if (hasSession) {
			await logoutAsync(req);
			res.locals.fullRefresh = true;
		}

		await plugin.cleanup({ res: res });
		return handleGuest.call(null, req, res);
	}

	if (Object.keys(req.headers.authorization).length && req.headers.hasOwnProperty(plugin.headers.authorization) && req.authorization[plugin.settings.authorization].length) {
		try {
			const uid = await plugin.process(req.header.authorization);
			if (uid === req.sub) {
				winston.verbose(`[session-sharing] Re-validated login for uid ${uid}, path ${req.originalUrl}`);
				return;
			}

			winston.verbose('[session-sharing] Processing login for uid ' + uid + ', path ' + req.originalUrl);
			await nbbAuthController.doLogin(req, uid);

			req.session.loginLock = true;
			const url = req.session.returnTo || req.originalUrl.replace(nconf.get('relative_path'), '');
			delete req.session.returnTo;
			res.redirect(nconf.get('relative_path') + url);
		} catch (error) {
			let handleAsGuest = false;

			switch (error.message) {
			case 'payload-invalid':
				winston.warn('[session-sharing] The passed-in payload was invalid and could not be processed');
				break;
			case 'no-match':
				winston.info('[session-sharing] Payload valid, but local account not found.  Assuming guest.');
				handleAsGuest = true;
				break;
			default:
				winston.warn('[session-sharing] Error encountered while parsing token: ' + error.message);
				break;
			}

			const data = await plugins.hooks.fire('filter:sessionSharing.error', {
				error,
				res: res,
				settings: plugin.settings,
				handleAsGuest: handleAsGuest,
			});

			if (data.handleAsGuest) {
				return handleGuest.call(error, req, res);
			}

			throw error;
		}
	} else if (hasSession) {
		// Has login session but no cookie, can assume "revalidate" behaviour
		const isAdmin = await user.isAdministrator(req.user.uid);

		if (plugin.settings.behaviour !== 'update' && (plugin.settings.adminRevalidate === 'on' || !isAdmin)) {
			winston.verbose(`[session-sharing] Found login session but no cookie, logging out user (was uid ${req.uid})`);
			await logoutAsync(req);
			res.locals.fullRefresh = true;
			return handleGuest(req, res);
		}
	} else {
		return handleGuest.call(null, req, res);
	}
};

plugin.generate = function (req, res) {
	if (!plugin.ready) {
		return res.sendStatus(404);
	}

	let payload = {};
	payload[plugin.settings['payload:id']] = 1;
	payload[plugin.settings['payload:username']] = 'testUser';
	payload[plugin.settings['payload:email']] = 'testUser@example.org';
	payload[plugin.settings['payload:firstName']] = 'Test';
	payload[plugin.settings['payload:lastName']] = 'User';
	payload[plugin.settings['payload:location']] = 'Testlocation';
	payload[plugin.settings['payload:birthday']] = '04/01/1981';
	payload[plugin.settings['payload:website']] = 'nodebb.org';
	payload[plugin.settings['payload:aboutme']] = 'I am just testing';
	payload[plugin.settings['payload:signature']] = 'T User';
	payload[plugin.settings['payload:groupTitle']] = 'TestUsers';
	payload[plugin.settings['payload:groups']] = ['test-group'];

	if (plugin.settings.payloadParent || plugin.settings['payload:parent']) {
		const parentKey = plugin.settings.payloadParent || plugin.settings['payload:parent'];
		const newPayload = {};
		newPayload[parentKey] = payload;
		payload = newPayload;
	}

	const token = jwt.sign(payload, plugin.settings.secret);
	res.cookie(plugin.settings.headerName, token, {
		maxAge: 1000 * 60 * 60 * 24 * 21,
		httpOnly: true,
		domain: plugin.settings.cookieDomain,
	});

	res.sendStatus(200);
};

plugin.addAdminNavigation = async (header) => {
	header.plugins.push({
		route: '/plugins/session-sharing',
		icon: 'fa-user-secret',
		name: 'Session Sharing',
	});

	return header;
};

plugin.reloadSettings = async (data) => {
	// If data argument is truthy, then it is the action hook from core
	if (data && data.plugin !== 'session-sharing') {
		return;
	}

	const settings = await meta.settings.get('session-sharing');

	// If "payload:parent" is found, but payloadParent is not, update the latter and delete the former
	if (!settings.payloadParent && settings['payload:parent']) {
		winston.verbose('[session-sharing] Migrating payload:parent to payloadParent');
		settings.payloadParent = settings['payload:parent'];
		await db.setObjectField('settings:session-sharing', 'payloadParent', settings.payloadParent);
		await db.deleteObjectField('settings:session-sharing', 'payload:parent');
	}

	if (!settings['payload:username'] && !settings['payload:firstName'] && !settings['payload:lastName'] && !settings['payload:fullname']) {
		settings['payload:username'] = 'username';
	}

	winston.info('[session-sharing] Settings OK');
	plugin.settings = _.defaults(_.pickBy(settings, Boolean), plugin.settings);
	plugin.ready = true;
};

plugin.appendTemplate = async (data) => {
	if (!data.req.session || !data.req.session.sessionSharing || !data.req.session.sessionSharing.banned) {
		return data;
	}

	const info = await user.getLatestBanInfo(data.req.session.sessionSharing.uid);

	data.templateData.sessionSharingBan = {
		ban: info,
		banned: true,
	};

	delete data.req.session.sessionSharing;
	return data;
};

plugin.saveReverseToken = async ({ req, userData: data }) => {
	if (!plugin.ready || !data || plugin.settings.reverseToken !== 'on') {
		return;	// no reverse token if secret not set
	}

	const res = req.res;
	const userData = await user.getUserFields(data.uid, ['sub', 'username', 'picture', 'reputation', 'postcount', 'banned']);
	userData.groups = (await groups.getUserGroups([data.uid])).pop();
	const token = jwt.sign(userData, plugin.settings.secret);

	res.cookie('nbb_token', token, {
		maxAge: meta.getSessionTTLSeconds() * 1000,
		httpOnly: true,
		domain: plugin.settings.cookieDomain,
	});

	winston.info(`[plugins/session-sharing] Saving reverse cookie for uid ${userData.uid}, session: ${req.session.id}`);
};

plugin.validateToken = async ({token}) => {
	const url = 'https://auth.dataporten.no/openid/userinfo';

	try {
		const response = await fetch(url, {
		headers: {
			Authorization: token
		}
		});

		if (response.ok) {
			const userInfo = await response.json();
			// Perform any additional validation checks on the userInfo object if needed
			winston.info('ID is valid:', userInfo);
			return userInfo
		} else {
			winston.warn('[session-sharing] ID is invalid');
		}
	} catch (error) {
		winston.warn('[session-sharing] An error occurred'), error;
		throw new Error('An error occurred while validating ID');
	} 
}


plugin.receiveID = function(req, res) {
	var hasSession = req.hasOwnProperty('user') && req.user.hasOwnProperty('sub') && parseInt(req.user.uid, 10) > 0;
	var hasAuthorization = req.headers.authorization?.length > 0;
  	var isBlacklisted = meta.blacklist.test(req.ip);

	if (isBlacklisted) {
		if (hasSession) {
			req.logout();
			res.locals.fullRefresh = true;
		}
	}

	if (hasAuthorization) {
		return plugin.process(req.header.authorization, function(err, uid) {
			if (err) {
				switch(err.message) {
					case 'banned':
						winston.info('[session-sharing] uid ' + uid + ' is banned, not logging them in');
						break;
					case 'payload-invalid':
						winston.warn('[session-sharing] The passed-in payload was invalid and could not be processed');
						break;
					default:
						winston.warn('[session-sharing] Error encountered while parsing authentication token: ' + err.message);
						break;
				}

				return res.sendStatus(500);
			}

			winston.info('[session-sharing] Processing login for uid ' + uid);
			req.uid = uid;
			nbbAuthController.doLogin(req, uid, function(err) {
				if (err) {
					return res.sendStatus(403);
				}

				if (!req.session.returnTo) {
					res.redirect(302, nconf.get('relative_path') + '/');
			  } else {
					var next = req.session.returnTo;
					delete req.session.returnTo;
					res.redirect(302, next);
				}
			});
		});
	} else if (hasSession) {
		// Has login session but no cookie, logout
		req.logout();
		res.locals.fullRefresh = true;
		handleGuest.apply(null, arguments);
	} else {
		handleGuest.apply(null, arguments);
	}

	res.sendStatus(200);
};

module.exports = plugin;
