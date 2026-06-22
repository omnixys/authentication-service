/**
 * Global Health Controller
 */

import { env } from '../config/env.js';
import { KafkaIndicator } from './kafka.indicator.js';
import { PrismaIndicator } from './prisma.indicator.js';
import { Controller, Get } from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckService,
  HttpHealthIndicator,
  HealthCheckResult,
  type HealthIndicatorFunction,
  type HealthIndicatorResult,
} from '@nestjs/terminus';
import { ValkeyService } from '@omnixys/cache';

const { KEYCLOAK_HEALTH_URL, TEMPO_HEALTH_URL, PROMETHEUS_HEALTH_URL } = env;

@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly http: HttpHealthIndicator,
    private readonly prisma: PrismaIndicator,
    private readonly kafka: KafkaIndicator,
    private readonly cache: ValkeyService,
  ) {}

  @Get('liveness')
  @HealthCheck()
  liveness(): Promise<HealthCheckResult> {
    return this.health.check([async () => ({ app: { status: 'up' } })]);
  }

  @Get('readiness')
  @HealthCheck()
  readiness(): Promise<HealthCheckResult> {
    const checks: HealthIndicatorFunction[] = [
      () => Promise.resolve({ app: { status: 'up' as const } }),
      () => this.prisma.isHealthy(),
      () => this.kafka.isHealthy(),
      () => this.cacheHealth(),
    ];
    if (KEYCLOAK_HEALTH_URL) {
      checks.push(() => this.http.pingCheck('keycloak', KEYCLOAK_HEALTH_URL));
    }
    if (TEMPO_HEALTH_URL) {
      checks.push(() => this.http.pingCheck('tempo', TEMPO_HEALTH_URL));
    }
    if (PROMETHEUS_HEALTH_URL) {
      checks.push(() => this.http.pingCheck('prometheus', PROMETHEUS_HEALTH_URL));
    }
    return this.health.check(checks);
  }

  private async cacheHealth(): Promise<HealthIndicatorResult> {
    const health = await this.cache.health();
    return {
      cache: {
        status: health.healthy ? 'up' : 'down',
        healthy: health.healthy,
        latencyMs: health.latencyMs,
        error: health.error,
      },
    };
  }
}
