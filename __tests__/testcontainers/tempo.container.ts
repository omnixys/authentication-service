import { GenericContainer, StartedTestContainer, Wait } from 'testcontainers';

export class TempoContainer {
  private container?: StartedTestContainer;

  async start() {
    this.container = await new GenericContainer('grafana/tempo:latest')
      .withExposedPorts(3200, 4318)
      .withCommand(['-config.file=/etc/tempo.yaml'])
      .withCopyContentToContainer([
        {
          content: `
server:
  http_listen_port: 3200

distributor:
  receivers:
    otlp:
      protocols:
        http:
          endpoint: 0.0.0.0:4318

storage:
  trace:
    backend: local
    local:
      path: /tmp/tempo
`,
          target: '/etc/tempo.yaml',
        },
      ])
      .withWaitStrategy(Wait.forHttp('/metrics', 3200))
      .withStartupTimeout(60_000)
      // .withLogConsumer((stream) => {
      //   stream.on('data', (line) => console.log('[TEMPO]', line.toString()));
      // })
      .start();

    const host = this.container.getHost();

    return {
      container: this.container,
      urlHttp: `http://${host}:${this.container.getMappedPort(3200)}`,
      urlOtel: `http://${host}:${this.container.getMappedPort(4318)}`,
    };
  }

  async stop() {
    await this.container?.stop();
  }
}
