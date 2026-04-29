import { AdminWriteService } from '../authentication/services/admin-write.service.js';
import { Injectable, Logger } from '@nestjs/common';
import { DelayedJob, DelayedJobHandler, DelayedJobKeys, ValkeyLockService } from '@omnixys/cache';

@Injectable()
@DelayedJobHandler()
export class UserDeleteHandler {
  private readonly logger = new Logger(UserDeleteHandler.name);

  constructor(
    private readonly adminWriteService: AdminWriteService,
    private readonly lock: ValkeyLockService,
  ) {}

  @DelayedJob(DelayedJobKeys.user.delete)
  async deleteUser(payload: { userId: string }) {
    const { userId } = payload;

    const lockKey = `lock:user-delete:${userId}`;
    const token = await this.lock.acquireLock(lockKey, 60000);

    if (!token) return;

    try {
      await this.adminWriteService.deleteUser(userId, 'sys');
      

      this.logger.log(`Deleted user ${userId}`);
    } finally {
      await this.lock.releaseLock(lockKey, token);
    }
  }
}
