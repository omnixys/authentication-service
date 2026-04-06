import { ValkeyRiskMemoryStore } from './valkey-risk-memory-store.adapter.js';
import { Global, Module } from '@nestjs/common';

@Global()
@Module({
  providers: [
    ValkeyRiskMemoryStore,
    {
      provide: 'RISK_MEMORY_STORE',
      useExisting: ValkeyRiskMemoryStore,
    },
    {
      provide: 'DEVICE_STORE',
      useExisting: ValkeyRiskMemoryStore,
    },
  ],
  exports: ['RISK_MEMORY_STORE', 'DEVICE_STORE'],
})
export class ZeroTrustValkeyAdapterModule {}
