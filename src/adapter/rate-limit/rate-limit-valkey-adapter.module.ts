import { ValkeyRateLimitStore } from './valkey-rate-limit-store.adapter.js';
import { Global, Module } from '@nestjs/common';

@Global()
@Module({
  providers: [
    ValkeyRateLimitStore,
    {
      provide: 'RATE_LIMIT_STORE',
      useExisting: ValkeyRateLimitStore,
    },
  ],
  exports: ['RATE_LIMIT_STORE'],
})
export class RateLimitValkeyAdapterModule {}
