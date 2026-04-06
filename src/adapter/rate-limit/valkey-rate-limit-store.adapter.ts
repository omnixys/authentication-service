import { Injectable } from '@nestjs/common';
import { ValkeyService } from '@omnixys/cache';
import { RateLimitStore } from '@omnixys/security';

@Injectable()
export class ValkeyRateLimitStore implements RateLimitStore {
  constructor(private readonly valkey: ValkeyService) {}

  async incr(key: string): Promise<number> {
    return this.valkey.increment(key);
  }

  async expire(key: string, seconds: number): Promise<void> {
    await this.valkey.expire(key, seconds);
  }

  async ttl(key: string): Promise<number> {
    return this.valkey.client.ttl(key);
  }
}
