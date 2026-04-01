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

import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import 'dotenv/config';

import { env } from '../config/env.js';
import { PrismaClient } from './generated/client.js';
import { setupPrismaSpans } from '@omnixys/observability';
import { PrismaPg } from '@prisma/adapter-pg';

const { DATABASE_URL } = env;

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    const adapter = new PrismaPg({
      connectionString: DATABASE_URL,
    });

    super({
      adapter,
      log: [{ emit: 'event', level: 'query' }],
    });
  }

  async onModuleInit(): Promise<void> {
    setupPrismaSpans(this);

    await this.$connect();
    console.debug('📦 Prisma connected');
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
    console.debug('📦 Prisma disconnected');
  }
}
