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

const fetch = require('node-fetch');

const controllers = require('./lib/controllers');
const nbbAuthController = require.main.require('./src/controllers/authentication');
const logoutAsync = util.promisify((req, callback) => req.logout(callback));

const userInfoUrl = 'https://auth.dataporten.no/openid/userinfo';
const memberStatusUrl = 'https://api.dataporten.no/userinfo/v1/userinfo';
const validRoles = ['employee'];

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
	'picture',
	'groups',
	'name',
]);

const plugin = {
	ready: false,
	settings: {
		name: 'appId',
		headerName: 'feideauthorization',
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

plugin.process = async (token, request, response) => {
	try{
		const userData = await validateToken(token, userInfoUrl)
		.then(userInfo => {
			if (userInfo) {
				return validateMemberStatus(token, memberStatusUrl, validRoles)
					.then(isValidMember => {
						if(isValidMember) {
							return userInfo;
						}
						response.status(403).send('Forbidden');
					});
			}
			return;
		})
		.catch(error => {
			console.error('An error occurred:', error);
		});
		if(userData) {
			const normalizedUserData = await plugin.normalizePayload(userData);
			const [uid, isNewUser] = await plugin.findOrCreateUser(normalizedUserData, request);
			await plugin.updateUserProfile(uid, userData, isNewUser);
			await plugin.updateUserGroups(uid, userData);
			await plugin.verifyUser(token, uid, isNewUser);
			return uid;
		}
	} catch (error){
		winston.error("Something went wrong", error);
		response.status(500).send('Internal Server Error');
	}
};

plugin.normalizePayload = async (payload) => {
	const userData = {};

	if (plugin.settings.payloadParent) {
		payload = payload[plugin.settings.payloadParent];
	}

	if (typeof payload !== 'object') {
		winston.warn('[feide-authentication] the payload is not an object', payload);
		throw new Error('payload-invalid');
	}

	payloadKeys.forEach(function (key) {
		const propName = plugin.settings['payload:' + key];
		if (payload[propName]) {
			userData[key] = payload[propName];
		}
	});

	if (!userData.sub) {
		winston.warn('[feide-authentication] No user id was given in payload');
		throw new Error('payload-invalid');
	}

	userData.fullname = (userData.fullname || userData.name || [userData.firstName, userData.lastName].join(' ')).trim();

	if (!userData.username) {
		userData.username = userData.fullname;
	}

	/* strip username from illegal characters */
	userData.username = userData.username.trim().replace(/[^'"\s\-.*0-9\u00BF-\u1FFF\u2C00-\uD7FF\w]+/, '-');

	if (!userData.username) {
		winston.warn('[feide-authentication] No valid username could be determined');
		throw new Error('payload-invalid');
	}

	if (userData.hasOwnProperty('groups') && !Array.isArray(userData.groups)) {
		winston.warn('[feide-authentication] Array expected for `groups` in JWT payload. Ignoring.');
		delete userData.groups;
	}

	winston.verbose('[feide-authentication] Payload verified');
	const data = await plugins.hooks.fire('filter:sessionSharing.normalizePayload', {
		payload: payload,
		userData: userData,
	});

	return data.userData;
};

plugin.verifyUser = async (token, uid, isNewUser) => {
	await plugins.hooks.fire('static:sessionSharing.verifyUser', {
		uid: uid,
		isNewUser: isNewUser,
		token: token.replace("Bearer",""),
	});

	// Check ban state of user
	const isBanned = await user.bans.isBanned(uid);

	// Reject if banned and settings dont allow banned users to login
	if (isBanned && !plugin.settings.allowBannedUsers) {
		throw new Error('banned');
	}
};

plugin.findOrCreateUser = async (userData, req) => {
	const { id } = userData;
	let isNewUser = false;
	let userId = null;
	let queries = [db.getSortedSetMembers(plugin.settings.name + ':feideId', userData.sub)];
	if (userData.email && userData.email.length) {
		queries = [...queries, db.sortedSetScore('email:uid', userData.email)];
	}
	let [feideId, mergeUid] = await Promise.all(queries);
	let uid = await db.sortedSetScore(plugin.settings.name + ':feideId', feideId);
	uid = parseInt(uid, 10);
	mergeUid = parseInt(mergeUid, 10);
	/* check if found something to work with */
	if (feideId) {
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
			winston.warn('[feide-authentication] Error while testing user existance', error);
		}
	}

	if (!userId && mergeUid && !isNaN(mergeUid)) {
		winston.info('[feide-authentication] Found user via their email, associating this id (' + id + ') with their NodeBB account');
		await db.sortedSetAdd(plugin.settings.name + ':uid', mergeUid, id);
		userId = mergeUid;
	}
	/* create the user from payload if necessary */
	winston.debug('createUser?', !userId);
	if (!userId && req.method == "POST") {
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
		winston.debug('[feide-authentication] Updating profile fields:', obj);
		obj.uid = uid;
		try {
			userObj = await user.updateProfile(uid, obj);

			// If it errors out, not that big of a deal, continue anyway.
			if (!userObj) {
				userObj = existingFields;
			}
		} catch (error) {
			winston.warn('[feide-authentication] Unable to update profile information for uid: ' + uid + '(' + error.message + ')');
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
	winston.verbose('[feide-authentication] No user found, creating a new user for this login');
	const uid = await user.create(_.pick(userData, profileFields));
	await db.sortedSetAdd(plugin.settings.name + ':feideId', uid, userData.sub);
	return uid;
};

plugin.addMiddleware = async function ({ req, res }) {
	if (!req.headers.feideauthorization) {
		return;
	}
	winston.verbose('[feide-authentication] test rebuild');
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
	//const hasLoginLock = req.session.hasOwnProperty('loginLock');
	/* if (
		!plugin.ready ||	// plugin not ready
		(plugin.settings.behaviour === 'trust') ||	// user logged in + "trust" behaviour
		((plugin.settings.behaviour === 'revalidate' || plugin.settings.behaviour === 'update'))
	) {
		// Let requests through under "update" or "revalidate" behaviour only if they're logging in for the first time
		delete req.session.loginLock;	// remove login lock for "update" or "revalidate" logins

		return;
	} */
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
	/* try {
		await meta.blacklist.test(req.ip);
	} catch (error) {
		/* if (hasSession) {
			await logoutAsync(req);
			res.locals.fullRefresh = true;
		}
		await plugin.cleanup({ res: res });
		return handleGuest.call(null, req, res);
	} */
	if (Object.keys(req.headers.feideauthorization).length && req.headers.hasOwnProperty(plugin.settings.headerName) && req.headers[plugin.settings.headerName].length) {
		try {
			const uid = await plugin.process(req.headers.feideauthorization, req, res);
			if(!uid) return;
			winston.verbose('[feide-authentication] Processing login for uid ' + uid + ', path ' + req.originalUrl);
			await nbbAuthController.doLogin(req, uid);
			req.session.loginLock = true;
			delete req.session.returnTo;
		} catch (error) {
			let handleAsGuest = false;

			switch (error.message) {
			case 'payload-invalid':
				winston.warn('[feide-authentication] The passed-in payload was invalid and could not be processed');
				break;
			case 'no-match':
				winston.info('[feide-authentication] Payload valid, but local account not found.  Assuming guest.');
				handleAsGuest = true;
				break;
			default:
				winston.warn('[feide-authentication] Error encountered while parsing token: ' + error.message);
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
			winston.verbose(`[feide-authentication] Found login session but no cookie, logging out user (was uid ${req.uid})`);
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
		winston.verbose('[feide-authentication] Migrating payload:parent to payloadParent');
		settings.payloadParent = settings['payload:parent'];
		await db.setObjectField('settings:session-sharing', 'payloadParent', settings.payloadParent);
		await db.deleteObjectField('settings:session-sharing', 'payload:parent');
	}

	if (!settings['payload:username'] && !settings['payload:firstName'] && !settings['payload:lastName'] && !settings['payload:fullname']) {
		settings['payload:username'] = 'username';
	}

	winston.info('[feide-authentication] Settings OK');
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

/* plugin.saveReverseToken = async ({ req, userData: data }) => {
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
 */
const fetchUserInfo = async (url, token) => {
	try {
	  const response = await fetch(url, {
		headers: {
		  Authorization: token,
		},
	  });
	  if (response.ok) {
		return await response.json();
	  }
	  winston.warn('[feide-authentication] ID is invalid');
	  return null;
	} catch (error) {
	  winston.warn('[feide-authentication] An error occurred', error);
	  throwError('An error occurred while validating ID');
	}
  };
  
const validateToken = async (token, userInfoUrl) => {
	const userInfo = await fetchUserInfo(userInfoUrl, token);
	if (userInfo) {
		winston.info('ID is valid:', userInfo);
		return userInfo;
	}
	return null;
};

const validateMemberStatus = async (token, memberStatusUrl, validRoles) => {
	const userInfo = await fetchUserInfo(memberStatusUrl, token);
	if (userInfo && validRoles.some(role => userInfo.eduPersonAffiliation.includes(role))) {
		winston.info('ID is valid for role:', userInfo);
		return true;
	}
	winston.warn('[feide-authentication] ID is invalid for role');
	return false;
};

module.exports = plugin;
