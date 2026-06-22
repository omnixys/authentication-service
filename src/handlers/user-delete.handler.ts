import { AdminWriteService } from '../authentication/services/admin-write.service.js';
import { Injectable } from '@nestjs/common';
import {
  DelayedJob,
  DelayedJobHandler,
  DelayedJobKeys,
  ValkeyLockService,
} from '@omnixys/cache';
import { OmnixysLogger } from '@omnixys/logger';

@Injectable()
@DelayedJobHandler()
export class UserDeleteHandler {
  private readonly logger;

  constructor(
    private readonly adminWriteService: AdminWriteService,
    private readonly lock: ValkeyLockService,
    logger: OmnixysLogger,
  ) {
    this.logger = logger.log(this.constructor.name);
  }

  @DelayedJob(DelayedJobKeys.user.delete)
  async deleteUser(payload: { userId: string }): Promise<void> {
    const { userId } = payload;

    const lockKey = `lock:user-delete:${userId}`;
    const token = await this.lock.acquireLock(lockKey, 60000);

    if (!token) {
      return;
    }

    try {
      await this.adminWriteService.deleteUser(userId, 'sys');

      this.logger.info('Delayed user deletion completed', { userId });
    } finally {
      await this.lock.releaseLock(lockKey, token);
    }
  }
}
