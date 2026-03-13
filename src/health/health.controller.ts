/**
 * Global Health Controller
 */

import { env } from '../config/env.js';
import { PrismaIndicator } from './prisma.indicator.js';
import { Controller, Get } from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckService,
  HttpHealthIndicator,
  HealthCheckResult,
} from '@nestjs/terminus';

@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly http: HttpHealthIndicator,
    private readonly prisma: PrismaIndicator,
  ) {}

  @Get('liveness')
  @HealthCheck()
  liveness(): Promise<HealthCheckResult> {
    return this.health.check([async () => ({ app: { status: 'up' } })]);
  }

  @Get('readiness')
  @HealthCheck()
  readiness(): Promise<HealthCheckResult> {
    return this.health.check([
      async () => ({ app: { status: 'up' } }),
      () => this.prisma.isHealthy(),
      () => this.http.pingCheck('keycloak', env.KEYCLOAK_HEALTH_URL),
      () => this.http.pingCheck('tempo', env.TEMPO_HEALTH_URL),
      () => this.http.pingCheck('prometheus', env.PROMETHEUS_HEALTH_URL),
    ]);
  }
}
