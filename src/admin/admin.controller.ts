/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

import { AdminService } from './admin.service.js';
import { Controller, Get, Post, UseGuards } from '@nestjs/common';
import { RealmRoleType } from '@omnixys/contracts';
import { CookieAuthGuard, RoleGuard, Roles } from '@omnixys/security';

/**
 * Controller providing REST endpoints for administrative operations
 * such as shutdown, restart, configuration reload, and health checks.
 *
 * @remarks
 * These endpoints are intended for internal or DevOps use only.
 * They are protected by an API key (or optionally JWT-based Keycloak guard)
 * to prevent unauthorized shutdown or restart commands.
 *
 * @category Administration
 * @since 1.0.0
 */
@Controller('admin')
@UseGuards(CookieAuthGuard, RoleGuard)
@Roles(RealmRoleType.ADMIN)
export class AdminController {
  /**
   * Creates a new instance of {@link AdminController}.
   *
   * @param adminService - Service that executes system-level operations such as restart or shutdown.
   */
  constructor(private readonly adminService: AdminService) {}

  /**
   * Returns a simple health report of the running service.
   *
   * @remarks
   * Can be used by monitoring tools or container health checks to verify availability.
   *
   * @example
   * ```bash
   * curl -H "x-api-key: super-secret-key" http://localhost:7501/admin/health
   * ```
   *
   * @returns A JSON object containing the service status and uptime.
   */
  @Get('health')
  async getHealth(): Promise<{ status: string; uptime: number }> {
    return this.adminService.getHealth();
  }

  /**
   * Triggers a controlled shutdown of the current service instance.
   *
   * @remarks
   * This method sends an immediate shutdown signal and gracefully exits the process.
   * Docker or systemd will not restart the container after a graceful shutdown
   * unless explicitly configured (`restart: always`).
   *
   * @example
   * ```bash
   * curl -X POST -H "x-api-key: super-secret-key" \
   *   http://localhost:7501/admin/shutdown
   * ```
   *
   * @returns A human-readable message confirming the shutdown.
   */
  @Post('shutdown')
  async shutdown(): Promise<string> {
    await this.adminService.shutdown();
    return 'Server shutting down...';
  }

  /**
   * Triggers a controlled restart of the current service instance.
   *
   * @remarks
   * The method exits the process with status code `1`.
   * Supervisors like Docker or PM2 detect this and restart the container automatically.
   *
   * @example
   * ```bash
   * curl -X POST -H "x-api-key: super-secret-key" \
   *   http://localhost:7501/admin/restart
   * ```
   *
   * @returns A human-readable message confirming the restart.
   */
  @Post('restart')
  async restart(): Promise<string> {
    await this.adminService.restart();
    return 'Server restarting...';
  }
}
