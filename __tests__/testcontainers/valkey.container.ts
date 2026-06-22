import { GenericContainer, Wait } from 'testcontainers';

export async function createValkeyContainer() {
  const password = 'test-password';

  const container = await new GenericContainer('valkey/valkey:latest')
    .withExposedPorts(6379)
    .withCommand(['valkey-server', '--requirepass', password]) // ✅ FIX
    .withWaitStrategy(Wait.forLogMessage('Ready to accept connections'))
    .start();

  const host = container.getHost();
  const port = container.getMappedPort(6379);

  return {
    container,
    url: `valkey://${host}:${port}`,
    password,
  };
}
