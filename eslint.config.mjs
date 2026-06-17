'use strict';

import serverConfig from 'eslint-config-nodebb';
import publicConfig from 'eslint-config-nodebb/public';
import prettier from 'eslint-config-prettier';

export default [...publicConfig, ...serverConfig, prettier];
