import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GenericContainer, Wait } from 'testcontainers';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function createKeycloakContainer() {
  const realmPath = path.resolve(__dirname, '../keycloak/omnixys-realm.json');

  const container = await new GenericContainer('quay.io/keycloak/keycloak:26.4')
    .withExposedPorts(8080)
    .withEnvironment({
      KC_BOOTSTRAP_ADMIN_USERNAME: 'admin',
      KC_BOOTSTRAP_ADMIN_PASSWORD: 'admin',
      KC_HTTP_ENABLED: 'true',
      KC_HOSTNAME_STRICT: 'false',
    })
    .withBindMounts([
      {
        source: realmPath,
        target: '/opt/keycloak/data/import/omnixys-realm.json',
      },
    ])
  .withCommand([
    'start-dev',
    '--import-realm',

    '--http-enabled=true',
    '--hostname-strict=false',
    '--proxy-headers=forwarded', 
  ])
    .withWaitStrategy(Wait.forHttp('/realms/omnixys', 8080).forStatusCode(200))
    .withStartupTimeout(120_000)
    .start();
  

  const host = container.getHost();
  const port = container.getMappedPort(8080);
  const url = `http://${host}:${port}`;


  console.log('✅ Keycloak ready:', url);

  return {
    container,
    url,
    realm: 'omnixys',
    clientId: 'nexys',
    clientSecret: 'uogDKQIP4d9aEgaYfT38BeN4JuOvwHJL',
  };
}
