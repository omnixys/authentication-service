import { env } from '../../config/env.js';
import { AuthenticationStateException } from '../errors/authentication.error.js';
import { PendingContact } from '../models/dtos/pending-contact.dto.js';
import { Injectable } from '@nestjs/common';
import { ValkeyKey, ValkeyService } from '@omnixys/cache';
import { randomUUID } from 'crypto';
import * as jose from 'jose';

const { PC_JWE_KEY, PC_TTL_SEC } = env;
@Injectable()
export class PendingContactService {
  constructor(private readonly cache: ValkeyService) {}

  /**
   * Returns the encryption key used for JWE.
   * Expected: 32 bytes base64 or raw utf8 string.
   */
  private getKeyMaterial(): Uint8Array {
    const raw = PC_JWE_KEY;
    if (!raw) {
      throw new AuthenticationStateException('pending-contact-key-missing');
    }

    // Try base64 first
    try {
      const buf = Buffer.from(raw, 'base64');
      if (buf.length === 32) {
        return buf;
      }
    } catch {
      // ignore and fall back
    }

    // Fallback: treat as UTF-8 secret
    const key = new TextEncoder().encode(raw);
    if (key.length !== 32) {
      throw new AuthenticationStateException('pending-contact-key-invalid');
    }
    return key;
  }

  /**
   * Stores encrypted contact information in Valkey.
   * Returns a generated contact-id.
   */
  async put(input: Omit<PendingContact, 'id' | 'createdAt'>, ttlSec = PC_TTL_SEC): Promise<string> {
    const id = randomUUID();
    const payload: PendingContact = {
      ...input,
      id,
      createdAt: Date.now(),
    };

    const key = this.getKeyMaterial();

    // Encrypt pending contact data
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(key);

    // Save encrypted data in Valkey
    await this.cache.set(
      ValkeyKey.pendingContact,
      {
        jwe,
        id,
      },
      ttlSec,
    );

    return id;
  }

  /**
   * Retrieves and decrypts the pending contact record.
   */
  async get(id: string): Promise<PendingContact | null> {
    const jwe = await this.cache.get(ValkeyKey.pendingContact, id);
    if (!jwe) {
      return null;
    }

    const key = this.getKeyMaterial();
    const { plaintext } = await jose.compactDecrypt(jwe, key);

    return JSON.parse(new TextDecoder().decode(plaintext)) as PendingContact;
  }

  /**
   * Deletes the pending contact record.
   */
  async delete(id: string): Promise<void> {
    await this.cache.delete(ValkeyKey.pendingContact, id);
  }
}
