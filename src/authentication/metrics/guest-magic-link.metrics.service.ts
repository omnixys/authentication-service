import { Injectable } from '@nestjs/common';
import type { GuestMagicLinkChannel } from '@omnixys/contracts-ts';

@Injectable()
export class GuestMagicLinkMetricsService {
  private issued = 0;
  private dispatched = 0;
  private verified = 0;
  private verifyErrors = 0;
  private rateLimited = 0;
  private readonly byChannel: Record<GuestMagicLinkChannel, number> = {
    EMAIL: 0,
    WHATSAPP: 0,
  };

  issue(channel: GuestMagicLinkChannel): void {
    this.issued += 1;
    this.byChannel[channel] += 1;
  }

  dispatch(): void {
    this.dispatched += 1;
  }

  recordVerified(): void {
    this.verified += 1;
  }

  recordVerifyError(): void {
    this.verifyErrors += 1;
  }

  recordRateLimit(): void {
    this.rateLimited += 1;
  }

  snapshot(): {
    issued: number;
    dispatched: number;
    verified: number;
    verifyErrors: number;
    rateLimited: number;
    byChannel: Record<GuestMagicLinkChannel, number>;
  } {
    return {
      issued: this.issued,
      dispatched: this.dispatched,
      verified: this.verified,
      verifyErrors: this.verifyErrors,
      rateLimited: this.rateLimited,
      byChannel: { ...this.byChannel },
    };
  }
}
