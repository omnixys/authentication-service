import { Injectable } from '@nestjs/common';
import type { HealthIndicatorResult } from '@nestjs/terminus';
import { KafkaLifecycleService } from '@omnixys/kafka';
import { OmnixysLogger } from '@omnixys/logger';

@Injectable()
export class KafkaIndicator {
  private readonly logger;

  constructor(
    private readonly kafka: KafkaLifecycleService,
    logger: OmnixysLogger,
  ) {
    this.logger = logger.log(this.constructor.name);
  }

  isHealthy(): HealthIndicatorResult {
    const health = this.kafka.health();
    if (!health.healthy) {
      this.logger.error('Kafka health check failed', { health });
    }

    return {
      kafka: {
        status: health.healthy ? 'up' : 'down',
        producer: health.producer.status,
        consumer: health.consumer.status,
      },
    };
  }
}
