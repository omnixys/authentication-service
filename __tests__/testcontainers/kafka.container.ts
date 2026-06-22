import { GenericContainer, Wait } from 'testcontainers';
import { Kafka } from 'kafkajs';

const TOPICS = [
  'invitation.deleteGuest.authentication',
  'invitation.deleteGuest.authentication.retry',
  'invitation.deleteGuestList.authentication',
  'invitation.deleteGuestList.authentication.retry',
];

export async function createKafkaContainer() {
  const hostPort = 19092;
  
  const container = await new GenericContainer('redpandadata/redpanda:latest')
    .withExposedPorts({
      container: 9092,
      host: hostPort,
    })
    .withCommand([
      'redpanda',
      'start',
      '--overprovisioned',
      '--smp',
      '1',
      '--memory',
      '512M',
      '--reserve-memory',
      '0M',
      '--node-id',
      '0',
      '--check=false',

      // LISTEN
      '--kafka-addr',
      'PLAINTEXT://0.0.0.0:9092',

      // 🔥 FIX: use container hostname internally
      '--advertise-kafka-addr',
      `PLAINTEXT://localhost:${hostPort}`,
    ])
    .withWaitStrategy(Wait.forLogMessage('Started Kafka API server'))
    .withStartupTimeout(60_000)
    .start();

  const host = container.getHost();
  const port = hostPort;

  const broker = `${host}:${port}`;

  const admin = new Kafka({
    clientId: 'authentication-e2e-provisioner',
    brokers: [broker],
  }).admin();
  await admin.connect();
  try {
    await admin.createTopics({
      topics: TOPICS.map((topic) => ({ topic, numPartitions: 1, replicationFactor: 1 })),
      waitForLeaders: true,
    });
  } finally {
    await admin.disconnect();
  }

  console.log('✅ Kafka ready:', broker);

  // container.logs().then((stream) => {
  //   stream.on('data', (line) => console.log('[KAFKA]', line.toString()));
  // });

  return {
    container,
    broker,
  };
}
