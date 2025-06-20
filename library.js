const winston = require.main.require('winston');
const nconf = require.main.require('nconf');

const pick = require('lodash/pick');

const meta = require.main.require('./src/meta');
const user = require.main.require('./src/user');
const groups = require.main.require('./src/groups');
const db = require.main.require('./src/database');
const plugins = require.main.require('./src/plugins');
const slugify = require.main.require('./src/slugify');

const fetch = require('node-fetch');
const nbbAuthController = require.main.require(
  './src/controllers/authentication',
);

const gatewayHost = process.env.API_GATEWAY_HOST
  ? `http://${process.env.API_GATEWAY_HOST}`
  : `https://api.test.ndla.no`;
const feideUserUrl = `${gatewayHost}/myndla-api/v1/users/`;
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
  'location',
  'userslug',
  'feideid',
];
const payloadKeys = profileFields.concat(['picture', 'groups', 'name', 'uid']);

const plugin = {
  ready: false,
  settings: {
    name: 'feideId',
    headerName: 'feideauthorization',
    cookieDomain: undefined,
    secret: '',
    behaviour: 'trust',
    adminRevalidate: 'off',
    noRegistration: 'off',
    payloadParent: undefined,
    allowBannedUsers: false,
    updateProfile: 'on',
  },
};

payloadKeys.forEach(function (key) {
  plugin.settings['payload:' + key] = key;
});

plugin.appendConfig = async (config) => {
  return config;
};

/* Log startup of plugin */
plugin.init = (data, callback) => {
  winston.info('[feide-authentication] Initializing...');
  callback();
};

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
  try {
    const { isValidMember, userInfo } = await getFeideUser(token, validRoles);
    if (!userInfo) {
      response.status(403).send('Forbidden');
      return;
    }

    if (!isValidMember) {
      response.status(403).send('Forbidden');
      return;
    }
    const normalizedUserData = await plugin.normalizePayload(userInfo);
    const [uid, isNewUser] = await plugin.findOrCreateUser(normalizedUserData);
    await plugin.updateUserProfile(uid, normalizedUserData, isNewUser);
    await plugin.updateUserGroups(uid, userInfo);
    await plugin.verifyUser(token, uid, isNewUser);
    return uid;
  } catch (error) {
    winston.error('Something went wrong', error);
    response.status(500).send('Internal Server Error');
  }
};

plugin.normalizePayload = async (payload) => {
  if (plugin.settings.payloadParent) {
    payload = payload[plugin.settings.payloadParent];
  }

  if (typeof payload !== 'object') {
    winston.warn(
      '[feide-authentication] the payload is not an object',
      payload,
    );
    throw new Error('payload-invalid');
  }

  const userData = {
    username: payload.username,
    email: payload.email,
    fullname: payload.fullname,
    location: payload.location,
    feideid: payload.feideid,
    userslug: slugify(payload.username.replace('@', '-')), // slugify does not convert @ any more
  };
  if (!userData.feideid) {
    winston.warn('[feide-authentication] No user id was given in payload');
    throw new Error('payload-invalid');
  }
  userData.fullname = (
    userData.fullname ||
    userData.name ||
    [userData.firstName, userData.lastName].join(' ')
  ).trim();
  if (!userData.username)
    userData.username = userData.fullname.replace(' ', '_');

  /* strip username from illegal characters */
  userData.username = userData.username
    .trim()
    .replace(/[^'"\s\-.*0-9\u00BF-\u1FFF\u2C00-\uD7FF\w]+/, '-');

  if (!userData.username) {
    winston.warn(
      '[feide-authentication] No valid username could be determined',
    );
    throw new Error('payload-invalid');
  }
  if (
    Object.prototype.hasOwnProperty.call(userData, 'groups') &&
    !Array.isArray(userData.groups)
  ) {
    winston.warn(
      '[feide-authentication] Array expected for `groups` in JWT payload. Ignoring.',
    );
    delete userData.groups;
  }

  winston.verbose('[feide-authentication] Payload verified');
  const data = await plugins.hooks.fire(
    'filter:sessionSharing.normalizePayload',
    {
      payload: payload,
      userData: userData,
    },
  );
  return data.userData;
};

plugin.verifyUser = async (token, uid, isNewUser) => {
  await plugins.hooks.fire('static:sessionSharing.verifyUser', {
    uid: uid,
    isNewUser: isNewUser,
    token: token.replace('Bearer', ''),
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
  let uid = await db.sortedSetScore(
    plugin.settings.name + ':uid',
    userData.feideid,
  );
  uid = parseInt(uid, 10);
  if (uid) {
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
      winston.warn(
        '[feide-authentication] Error while testing user existance',
        error,
      );
    }
  }

  /* create the user from payload if necessary */
  winston.debug('createUser?', !uid);
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
  winston.debug(
    'consider updateProfile?',
    isNewUser || plugin.settings.updateProfile === 'on',
  );
  /* only update the profile on a new account, since some fields are not initialized by NodeBB */
  if (!isNewUser) {
    return;
  }

  const existingFields = await user.getUserFields(uid, profileFields);
  const obj = profileFields.reduce((result, field) => {
    if (
      typeof userData[field] !== 'undefined' &&
      existingFields[field] !== userData[field]
    ) {
      result[field] = userData[field];
    }
    return result;
  }, {});
  try {
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        db.setObjectField('user:' + uid, key, obj[key]);
      }
    }
  } catch (error) {
    winston.warn(
      '[feide-authentication] Unable to update profile information for uid: ' +
        uid +
        '(' +
        error.message +
        ')',
    );
  }
};

plugin.updateUserGroups = async (uid, userData) => {
  if (!userData.groups || !Array.isArray(userData.groups)) {
    return;
  }

  // Retrieve user groups
  let [userGroups] = await groups.getUserGroupsFromSet('groups:createtime', [
    uid,
  ]);
  // Normalize user group data to just group names
  userGroups = userGroups.map((groupObj) => groupObj.name);

  // Build join and leave arrays
  let join = userData.groups.filter((name) => !userGroups.includes(name));
  if (plugin.settings.syncGroupList === 'on') {
    join = join.filter((group) => plugin.settings.syncGroups.includes(group));
  }

  let leave = userGroups.filter((name) => {
    // `registered-users` is always a joined group
    if (name === 'registered-users') {
      return false;
    }

    return !userData.groups.includes(name);
  });
  if (plugin.settings.syncGroupList === 'on') {
    leave = leave.filter((group) => plugin.settings.syncGroups.includes(group));
  }

  await executeJoinLeave(uid, join, leave);
};

async function executeJoinLeave(uid, join, leave) {
  await Promise.all([
    (async () => {
      if (plugin.settings.syncGroupJoin !== 'on') {
        return;
      }

      await Promise.all(join.map((name) => groups.join(name, uid)));
    })(),
    (async () => {
      if (plugin.settings.syncGroupLeave !== 'on') {
        return;
      }

      await Promise.all(leave.map((name) => groups.leave(name, uid)));
    })(),
  ]);
}

plugin.createUser = async (userData) => {
  const email = userData.email;
  winston.verbose(
    '[feide-authentication] No user found, creating a new user for this login',
  );
  const picked = pick(userData, profileFields);
  const uid = await user.create(picked);
  await db.sortedSetAdd(plugin.settings.name + ':uid', uid, userData.feideid);
  if (email) {
    await user.setUserField(uid, 'email', email);
    await user.email.confirmByUid(uid);
  }

  return uid;
};

plugin.addMiddleware = async function ({ req, res }) {
  if (!req.headers[plugin.settings.headerName]) {
    return;
  }
  const { hostWhitelist, guestRedirect } =
    await meta.settings.get('session-sharing');

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
    if (
      guestRedirect &&
      !req.originalUrl.startsWith(nconf.get('relative_path') + '/login?local=1')
    ) {
      // If a guest redirect is specified, follow it
      res.redirect(
        guestRedirect.replace(
          '%1',
          encodeURIComponent(
            req.protocol + '://' + req.get('host') + req.originalUrl,
          ),
        ),
      );
    } else if (res.locals.fullRefresh === true) {
      res.redirect(nconf.get('relative_path') + req.url);
    }
  }

  if (Object.keys(req.headers[plugin.settings.headerName]).length) {
    try {
      const uid = await plugin.process(
        req.headers[plugin.settings.headerName],
        req,
        res,
      );
      if (!uid) return;
      winston.info(
        '[feide-authentication] Processing login for uid ' +
          uid +
          ', path ' +
          req.originalUrl,
      );
      await nbbAuthController.doLogin(req, uid);
      req.session.loginLock = true;
      delete req.session.returnTo;
    } catch (error) {
      switch (error.message) {
        case 'payload-invalid':
          winston.warn(
            '[feide-authentication] The passed-in payload was invalid and could not be processed',
          );
          break;
        case 'no-match':
          winston.info(
            '[feide-authentication] Payload valid, but local account not found.  Assuming guest.',
          );
          break;
        default:
          winston.warn(
            '[feide-authentication] Error encountered while parsing token: ' +
              error.message,
          );
          break;
      }
      await plugins.hooks.fire('filter:sessionSharing.error', {
        error,
        res: res,
        settings: plugin.settings,
      });

      throw error;
    }
  } else {
    return handleGuest.call(null, req, res);
  }
};

plugin.appendTemplate = async (data) => {
  if (
    !data.req.session ||
    !data.req.session.sessionSharing ||
    !data.req.session.sessionSharing.banned
  ) {
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

const fetchUserInfo = async (token, headers) => {
  try {
    const response = await fetch(feideUserUrl, {
      headers: {
        [headers]: token,
      },
    });
    if (response.ok) {
      return await response.json();
    }
    winston.warn('[feide-authentication] ID is invalid');
    return null;
  } catch (error) {
    winston.warn('[feide-authentication] An error occurred', error);
    throw Error('An error occurred while validating ID');
  }
};

const getFeideUser = async (token, validRoles) => {
  const feideInfo = await fetchUserInfo(token, 'feideauthorization');
  if (
    feideInfo &&
    validRoles.some((role) => feideInfo.role === role) &&
    feideInfo.arenaEnabled === true
  ) {
    const transformedUserInfo = await extractUserInfo(feideInfo);
    return {
      isValidMember: true,
      userInfo: transformedUserInfo,
    };
  }
  if (feideInfo !== null) {
    if (!validRoles.some((role) => feideInfo.role === role)) {
      winston.warn('[Feide-authentication] User role is not valid.', {
        userId: feideInfo.id,
        userRole: feideInfo.role,
        validRoles,
      });
    }
    if (feideInfo.arenaEnabled === false) {
      winston.warn(
        '[Feide-authentication] User profile has arena enabled set to false.',
        {
          userId: feideInfo.id,
          arenaEnabled: feideInfo.arenaEnabled,
        },
      );
    }
  }
  return { isValidMember: false };
};

const extractUserInfo = async (jsonData) => {
  const primarySchoolGroup = jsonData.groups.find(
    (group) => group.isPrimarySchool,
  );
  return {
    fullname: jsonData.displayName,
    feideid: jsonData.feideId,
    email: jsonData.email,
    username: jsonData.username,
    role: jsonData.role,
    location: primarySchoolGroup
      ? primarySchoolGroup.displayName
      : jsonData.organization,
  };
};

module.exports = plugin;
