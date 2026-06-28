import { Injectable } from '@nestjs/common';
import { ValkeyService } from '@omnixys/cache';
import { RiskMemoryStore } from '@omnixys/security';

@Injectable()
export class ValkeyRiskMemoryStore implements RiskMemoryStore {
  constructor(private readonly valkey: ValkeyService) {}

  async incr(key: string): Promise<number> {
    return this.valkey.increment(key);
  }

  async get(key: string): Promise<string | null> {
    return this.valkey.rawGet(key);
  }

  async set(
    key: string,
    value: string,
    options?: { EX?: number },
  ): Promise<void> {
    await this.valkey.rawSet(key, value, options?.EX);
  }

  async expire(key: string, seconds: number): Promise<void> {
    await this.valkey.expire(key, seconds);
  }

  async del(key: string): Promise<void> {
    await this.valkey.client.del(this.valkey.key(key));
  }
}
