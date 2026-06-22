import { PostgreSqlContainer } from '@testcontainers/postgresql';

export async function createPostgresContainer() {
  const container = await new PostgreSqlContainer('postgres:16')
    .withDatabase('testdb')
    .withUsername('test')
    .withPassword('test')
    .start();

  return {
    container,
    url: container.getConnectionUri(),
  };
}
