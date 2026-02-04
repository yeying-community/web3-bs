import {
  getProvider,
  requestAccounts,
  authFetch,
  refreshAccessToken,
  getAccessToken,
  createInvocationUcan,
  authUcanFetch,
  initDappSession,
} from '@yeying-community/web3-bs';

async function connectAndLogin() {
  const provider = await getProvider();
  if (!provider) {
    throw new Error('No injected wallet provider');
  }

  const accounts = await requestAccounts({ provider });
  const address = accounts[0];
  if (!address) {
    throw new Error('No account returned');
  }

  const appId = typeof window !== 'undefined' ? window.location.host || '127.0.0.1:8001' : '127.0.0.1:8001';
  const appCap = { resource: `app:${appId}`, action: 'write' };
  const profileCap = { resource: 'profile', action: 'read' };

  const session = await initDappSession({
    provider,
    address,
    appAuth: {
      baseUrl: 'http://127.0.0.1:3203/api/v1/public/auth',
      storeToken: false,
    },
    webdav: {
      baseUrl: 'http://127.0.0.1:6065',
      audience: 'did:web:127.0.0.1:6065',
      appId,
      capabilities: [appCap, profileCap],
      invocationCapabilities: [appCap],
    },
  });

  if (!session.appLogin) {
    throw new Error('Login failed');
  }

  console.log('token', session.appLogin.token);

  const profileRes = await authFetch('http://127.0.0.1:3203/api/v1/public/profile', { method: 'GET' }, {
    baseUrl: 'http://127.0.0.1:3203/api/v1/public/auth',
    storeToken: false,
  });

  console.log('profile', await profileRes.json());

  const refreshed = await refreshAccessToken({
    baseUrl: 'http://127.0.0.1:3203/api/v1/public/auth',
    storeToken: false,
  });

  console.log('refreshed token', refreshed.token);
  console.log('current token', getAccessToken({ storeToken: false }));

  // WebDAV Storage (requires webdav server running on 6065)
  try {
    const webdav = session.webdavClient;
    const appDir = session.webdavAppDir || '/';
    if (webdav) {
      const listing = await webdav.listDirectory(appDir);
      console.log('webdav list', listing);
      await webdav.upload(`${appDir}/web3-bs.txt`, 'Hello WebDAV');
      console.log('webdav uploaded');
      const content = await webdav.downloadText(`${appDir}/web3-bs.txt`);
      console.log('webdav download', content);
    }
  } catch (error) {
    console.warn('webdav not available', error);
  }

  if (!session.ucanSession || !session.ucanRoot) {
    throw new Error('UCAN session unavailable');
  }

  const ucanToken = await createInvocationUcan({
    issuer: session.ucanSession,
    audience: 'did:web:127.0.0.1:3203',
    capabilities: [profileCap],
    proofs: [session.ucanRoot],
  });
  const ucanRes = await authUcanFetch(
    'http://127.0.0.1:3203/api/v1/public/profile',
    { method: 'GET' },
    { ucan: ucanToken }
  );
  console.log('ucan profile', await ucanRes.json());
}

connectAndLogin().catch(error => {
  console.error('Login failed:', error);
});
