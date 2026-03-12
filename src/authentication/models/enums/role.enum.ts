/* eslint-disable @typescript-eslint/no-non-null-assertion */
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

import { registerEnumType } from '@nestjs/graphql';
import { RealmRole } from '@omnixys/contracts';

export interface RoleData {
  id: string;
  name: string;
}

registerEnumType(RealmRole, { name: 'RealmRole' });

/** Enum → actual Keycloak role name (keep as defined in Keycloak) */
export const ENUM_TO_KC: Record<RealmRole, string> = {
  [RealmRole.ADMIN]: 'ADMIN',

  [RealmRole.SUPREME]: 'SUPREME',
  [RealmRole.ELITE]: 'ELITE',
  [RealmRole.BASIC]: 'BASIC',

  [RealmRole.USER]: 'USER',
  [RealmRole.GUEST]: 'GUEST',
};

/** Keycloak name/string → enum (robust & case-insensitive) */
export const KC_TO_ENUM: Record<string, RealmRole> = {
  // ADMIN
  admin: RealmRole.ADMIN,
  ADMIN: RealmRole.ADMIN,

  // TIERS
  supreme: RealmRole.SUPREME,
  SUPREME: RealmRole.SUPREME,

  elite: RealmRole.ELITE,
  ELITE: RealmRole.ELITE,

  basic: RealmRole.BASIC,
  BASIC: RealmRole.BASIC,

  // USER / GUEST
  user: RealmRole.USER,
  USER: RealmRole.USER,

  guest: RealmRole.GUEST,
  GUEST: RealmRole.GUEST,
};

/** One string → enum (or null if unknown) */
export function roleStrToEnum(s: string | undefined | null): RealmRole | null {
  if (!s) {
    return null;
  }

  const raw = String(s).trim();

  // Normalize common prefixes and separators (Keycloak/client exports vary)
  // e.g. "ROLE_ADMIN", "realm:admin", "checkpoint-api:ADMIN"
  const normalized = raw
    .replace(/^ROLE_/i, '')
    .replace(/^REALM:/i, '')
    .replace(/^CLIENT:/i, '')
    .trim();

  // Support "clientId:ROLE" patterns by taking the last segment
  const lastSegment = normalized.includes(':')
    ? normalized.split(':').pop()!.trim()
    : normalized;

  return (
    KC_TO_ENUM[lastSegment] ?? KC_TO_ENUM[lastSegment.toLowerCase()] ?? null
  );
}

/** Strings → deduplicated enum array */
export function toEnumRoles(
  list: Array<string | null | undefined>,
): RealmRole[] {
  const out: RealmRole[] = [];
  const seen = new Set<RealmRole>();

  for (const raw of list) {
    const r = roleStrToEnum(raw ?? undefined);
    if (r && !seen.has(r)) {
      seen.add(r);
      out.push(r);
    }
  }
  return out;
}

/** Enum → Keycloak string */
export function enumToKcName(r: RealmRole): string {
  return ENUM_TO_KC[r] ?? String(r);
}

/**
 * Resolve ONE effective role from many raw roles.
 * Priority order: admin/security/event_admin > tiers > user/guest > anon
 */
export function resolveEffectiveRole(
  isAuthenticated: boolean,
  raw?: string[] | null,
): RealmRole {
  if (!isAuthenticated) {
    return RealmRole.GUEST;
  }

  const roles = toEnumRoles(raw ?? []);

  // Hard priority list (first match wins)
  const PRIORITY: RealmRole[] = [
    RealmRole.ADMIN,

    RealmRole.SUPREME,
    RealmRole.ELITE,
    RealmRole.BASIC,

    RealmRole.USER,
    RealmRole.GUEST,
  ];

  for (const p of PRIORITY) {
    if (roles.includes(p)) {
      return p;
    }
  }

  // Authenticated but no known roles
  return RealmRole.GUEST;
}

/** Mapping internal role → Keycloak role name (alias for enumToKcName) */
export const ROLE_NAME_MAP: Record<RealmRole, string> = {
  [RealmRole.ADMIN]: 'ADMIN',

  [RealmRole.SUPREME]: 'SUPREME',
  [RealmRole.ELITE]: 'ELITE',
  [RealmRole.BASIC]: 'BASIC',

  [RealmRole.USER]: 'USER',
  [RealmRole.GUEST]: 'GUEST',
};
