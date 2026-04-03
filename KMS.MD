# KMS Integration Analysis — Open Mercato × Encedo

**Date:** 2026-04-03  
**Author:** KMS Architecture Review  
**Scope:** Field-level encryption subsystem (`packages/shared/src/lib/encryption/`) and its KMS backend

---

## 1. How KMS Currently Works in Open Mercato

### 1.1 High-Level Overview

Open Mercato implements **per-tenant, per-field encryption at rest** using AES-256-GCM. The system
encrypts sensitive PII fields (email, address, names, deal titles, etc.) transparently at the ORM layer
without application code needing to handle raw cryptography.

The encryption pipeline looks like this:

```
Application code (CRUD routes)
        │
        ▼
MikroORM Subscriber (TenantEncryptionSubscriber)
        │
        ▼
TenantDataEncryptionService
        │  ┌─────────────────────────────────────────────────┐
        ├─►│  EncryptionMap (DB table)                       │
        │  │  entity_id × tenant_id × organization_id →     │
        │  │  { fields: [{ field, hashField }] }             │
        │  └─────────────────────────────────────────────────┘
        │  ┌─────────────────────────────────────────────────┐
        └─►│  KmsService                                     │
           │  getTenantDek(tenantId) → { key: base64 }       │
           └─────────────────────────────────────────────────┘
                    │
                    ▼
          encryptWithAesGcm / decryptWithAesGcm
          (iv:ciphertext:tag:v1 format)
```

### 1.2 Encryption Map

`EncryptionMap` is a database table (`encryption_maps`) that declares **which fields of which entity
should be encrypted for a given tenant/organization scope**:

| Column | Purpose |
|--------|---------|
| `entity_id` | String identifier like `customers:customer_entity` |
| `tenant_id` | Scope: per-tenant (or NULL = all tenants) |
| `organization_id` | Scope: per-org (or NULL = all orgs) |
| `fields_json` | Array of `{ field: string, hashField?: string }` |
| `is_active` | Soft-disable without deleting |

Default encryption maps are seeded via CLI (`mercato entities seed-encryption --tenant <uuid>`) and
cover PII fields across: `auth:user`, `customers:*`, `sales:sales_order`, and many more
(see `packages/core/src/modules/entities/lib/encryptionDefaults.ts`).

### 1.3 DEK (Data Encryption Key) Lifecycle

Each tenant gets its own **Data Encryption Key (DEK)**:

1. **Creation**: `KmsService.createTenantDek(tenantId)` — generates random 32-byte AES-256 key,
   stores it in Vault at path `secret/data/tenant_key_<tenantId>`
2. **Retrieval**: `KmsService.getTenantDek(tenantId)` — reads from Vault, cached in memory for 15 min
3. **Rotation**: `mercato entities rotate-encryption-key --tenant <uuid>` — re-encrypts all fields
4. **Teardown**: `mercato entities decrypt-database --tenant <uuid> --confirm <uuid>` — decrypts and optionally deactivates maps

### 1.4 AES-GCM Wire Format

Encrypted values are stored as a colon-separated string:

```
<iv_base64>:<ciphertext_base64>:<authtag_base64>:v1
```

- IV: 12 random bytes (per-value)
- Tag: 16 bytes (AES-GCM authentication)
- Version suffix `v1` used for format detection and future upgrade path

For text-lookup fields (e.g. `email`), a deterministic SHA-256 hash is stored in a companion column
(`email_hash`) to allow equality searches without decrypting.

---

## 2. Architecture of the Encryption Subsystem

### 2.1 KmsService Interface (the extension point)

```typescript
// packages/shared/src/lib/encryption/kms.ts
export interface KmsService {
  getTenantDek(tenantId: string): Promise<TenantDek | null>
  createTenantDek(tenantId: string): Promise<TenantDek | null>
  isHealthy(): boolean
}

export type TenantDek = {
  tenantId: string
  key: string   // raw DEK as base64 — 32 bytes
  fetchedAt: number
}
```

This is a **clean interface**. Any KMS can be plugged in by implementing it.

### 2.2 Implemented KMS Backends

| Class | Location | When active |
|-------|----------|-------------|
| `HashicorpVaultKmsService` | `kms.ts` | `VAULT_ADDR` + `VAULT_TOKEN` configured |
| `DerivedKmsService` | `kms.ts` | Fallback: derives DEK from a shared secret via PBKDF2 |
| `FallbackKmsService` | `kms.ts` | Wrapper: tries primary, falls back to secondary |
| `NoopKmsService` | `kms.ts` | Encryption disabled globally |

### 2.3 createKmsService() — the factory function

```typescript
export function createKmsService(): KmsService {
  if (!isTenantDataEncryptionEnabled()) return new NoopKmsService()

  const primary = new HashicorpVaultKmsService()         // VAULT_ADDR + VAULT_TOKEN
  const derived = resolveDerivedKeySecret()               // env fallback
  const fallback = derived ? new DerivedKmsService(...)  : null

  if (!primary.isHealthy()) {
    return fallback ?? new NoopKmsService()               // Vault down → derived key
  }

  if (fallback) {
    return new FallbackKmsService(primary, fallback)      // Vault + fallback chain
  }

  return primary                                          // Vault only
}
```

**This is the single injection point** — changing the KMS backend means replacing or extending this factory.

### 2.4 HashicorpVaultKmsService — Current Implementation

- Protocol: **Vault HTTP API v1** (`GET/POST /v1/<mountPath>/tenant_key_<tenantId>`)
- Auth: static token (`X-Vault-Token` header)
- Storage: Vault KV v2 secrets engine (`secret/data/` by default)
- Key format: `{ data: { key: "<base64>" } }` in Vault JSON envelope
- In-process DEK cache: TTL = 15 minutes
- Health flag: set to `false` on HTTP 5xx or network error

### 2.5 Environment Variables

| Variable | Purpose |
|----------|---------|
| `TENANT_DATA_ENCRYPTION` | Master toggle (default: `true`) |
| `TENANT_DATA_ENCRYPTION_DEBUG` | Verbose logging |
| `VAULT_ADDR` | HashiCorp Vault endpoint |
| `VAULT_TOKEN` | Vault access token |
| `VAULT_KV_PATH` | KV2 mount path (default: `secret/data`) |
| `TENANT_DATA_ENCRYPTION_FALLBACK_KEY` | Secret for derived-key fallback |
| `TENANT_DATA_ENCRYPTION_KEY` | Legacy secondary fallback secret |

### 2.6 ORM Integration

`TenantEncryptionSubscriber` (MikroORM `EventSubscriber`) intercepts:
- `beforeCreate` / `beforeUpdate` → calls `encryptEntityPayload()`
- Read operations via `findWithDecryption` / `findOneWithDecryption` wrappers

Encryption is **transparent** — application code reads/writes plaintext, the subscriber + service
handle all encryption/decryption automatically based on `EncryptionMap` configuration.

### 2.7 CLI Commands (entities module)

| Command | Purpose |
|---------|---------|
| `mercato entities seed-encryption --tenant <uuid>` | Seed EncryptionMap + create DEK |
| `mercato entities rotate-encryption-key --tenant <uuid>` | Re-encrypt under new DEK |
| `mercato entities decrypt-database --tenant <uuid> --confirm <uuid>` | Full decrypt + optional map deactivation |

---

## 3. Proposal: Switching KMS from HashiCorp Vault to Encedo

### 3.1 Why Encedo?

Encedo HEM (Hardware Encryption Module) brings several advantages over HashiCorp Vault for DEK management:

| Feature | HashiCorp Vault | Encedo HEM |
|---------|----------------|-----------|
| Key storage | Software-defined (HSM optional add-on) | Hardware-rooted (tamper-proof) |
| Key export | Possible with appropriate policy | Never — keys never leave HSM |
| Deployment | Cluster/agent required | PPA: USB key; EPA: cloud appliance |
| Authentication | Token / AppRole / LDAP | HW-bound identity (PPA) / mutual TLS (EPA) |
| Audit trail | Log → SIEM integration | On-device immutable log |
| FIPS 140-2/3 | Vault Enterprise only | Native (hardware) |
| Latency | ~1–5 ms (network + software) | ~0.5–2 ms (PPA local) / similar to Vault (EPA) |

For open-mercato's field-level encryption, Encedo can serve as a drop-in **DEK store** (EPA REST API)
or provide an even stronger model where the DEK **never leaves the hardware** (signing model).

### 3.2 Integration Architecture Options

#### Option A — Encedo EPA as REST KMS (drop-in replacement)

The simplest path. Encedo EPA exposes a REST API for key management. We implement
`EncedoKmsService implements KmsService` that talks to the EPA API instead of Vault.

```
Open Mercato → EncedoKmsService → EPA REST API → HSM
```

**Pros:** Minimal code change, fully transparent to encryption subsystem.  
**Cons:** DEK bytes still travel over the network (REST response).

#### Option B — Encedo EPA as Envelope KMS (recommended for production)

Encedo EPA acts as a **wrapping KMS**: it wraps/unwraps DEKs using a Hardware Root Key (HRK) that
never leaves the HSM. Open Mercato stores **wrapped DEK blobs** in its own database, and calls
Encedo only to unwrap them on first use.

```
Provisioning:  generateDek() → raw DEK
               → EncedoKmsService.wrapDek(rawDek, tenantId) → wrappedDek blob
               → stored in encryption_maps or a new dek_store table

Runtime read:  wrappedDek from DB
               → EncedoKmsService.unwrapDek(wrappedDek) → raw DEK (in memory only)
               → AES-GCM decrypt as before
```

**Pros:** Encedo becomes authoritative source of key material (cryptographic binding to hardware).
The database stores only wrapped blobs — useless without the HSM.  
**Cons:** Requires schema change (DEK store table) + new CLI commands for DEK wrapping migration.

#### Option C — Encedo PPA + Offline-capable DEK derivation

For deployments where the USB key (PPA) is intermittently available (e.g. on-prem operator),
use PPA to provision per-tenant secrets during setup; derive per-tenant DEKs from the PPA-signed
seed (similar to current `DerivedKmsService`). This is a write-once hardware-bootstrap model.

**Pros:** Air-gap / offline-capable after initial provisioning.  
**Cons:** DEKs are deterministically derived (lower entropy than hardware-random), requires physical
PPA access for tenant onboarding.

### 3.3 Recommended Approach: Option A as MVP, Option B as Production Target

**Phase 1 — MVP (Option A):** implement `EncedoEpaKmsService` as a new class in `kms.ts` (or
a new file `kms-encedo.ts`) that satisfies `KmsService`. Extend `createKmsService()` to check for
`ENCEDO_EPA_URL` / `ENCEDO_EPA_TOKEN` env vars and use the new service as primary.

**Phase 2 — Production (Option B):** introduce `EncedoEnvelopeKmsService` with wrapping/unwrapping.
Add a `dek_store` table (wrappedKey column), migrate existing Vault DEKs via a CLI command
(`mercato entities migrate-dek --from vault --to encedo --tenant <uuid>`).

### 3.4 Implementation Plan (Option A — MVP)

#### New File: `packages/shared/src/lib/encryption/kms-encedo.ts`

```typescript
import type { KmsService, TenantDek } from './kms'
import { generateDek } from './aes'

type EncedoEpaOpts = {
  epaUrl?: string      // ENCEDO_EPA_URL
  epaToken?: string    // ENCEDO_EPA_TOKEN
  ttlMs?: number
}

export class EncedoEpaKmsService implements KmsService {
  private cache = new Map<string, TenantDek>()
  private readonly epaUrl: string
  private readonly epaToken: string
  private readonly ttlMs: number
  private healthy = true

  constructor(opts: EncedoEpaOpts = {}) {
    this.epaUrl = (opts.epaUrl ?? process.env.ENCEDO_EPA_URL ?? '').trim()
    this.epaToken = (opts.epaToken ?? process.env.ENCEDO_EPA_TOKEN ?? '').trim()
    this.ttlMs = opts.ttlMs ?? 15 * 60 * 1000
    if (!this.epaUrl || !this.epaToken) {
      this.healthy = false
    }
  }

  isHealthy(): boolean { return this.healthy }

  async getTenantDek(tenantId: string): Promise<TenantDek | null> {
    const cached = this.cacheHit(tenantId)
    if (cached) return cached

    // GET /v1/keys/tenant_<tenantId>
    const res = await fetch(`${this.epaUrl}/v1/keys/tenant_${tenantId}`, {
      headers: { Authorization: `Bearer ${this.epaToken}` },
    })
    if (!res.ok) {
      if (res.status >= 500) this.healthy = false
      return null
    }
    const body = await res.json() as { key: string }
    return this.remember({ tenantId, key: body.key, fetchedAt: Date.now() })
  }

  async createTenantDek(tenantId: string): Promise<TenantDek | null> {
    const key = generateDek()
    // POST /v1/keys/tenant_<tenantId>  { key }
    const res = await fetch(`${this.epaUrl}/v1/keys/tenant_${tenantId}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.epaToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ key }),
    })
    if (!res.ok) {
      if (res.status >= 500) this.healthy = false
      return null
    }
    return this.remember({ tenantId, key, fetchedAt: Date.now() })
  }

  private cacheHit(tenantId: string): TenantDek | null {
    const entry = this.cache.get(tenantId)
    if (!entry || Date.now() - entry.fetchedAt > this.ttlMs) {
      this.cache.delete(tenantId)
      return null
    }
    return entry
  }

  private remember(dek: TenantDek): TenantDek {
    this.cache.set(dek.tenantId, dek)
    return dek
  }
}
```

#### Changes to `createKmsService()` in `kms.ts`

```typescript
import { EncedoEpaKmsService } from './kms-encedo'

export function createKmsService(): KmsService {
  if (!isTenantDataEncryptionEnabled()) return new NoopKmsService()

  // --- Encedo EPA (new primary option) ---
  const encedoEpaUrl = normalizeEnv(process.env.ENCEDO_EPA_URL)
  const encedoEpaToken = normalizeEnv(process.env.ENCEDO_EPA_TOKEN)
  if (encedoEpaUrl && encedoEpaToken) {
    const encedoPrimary = new EncedoEpaKmsService()
    const derived = resolveDerivedKeySecret()
    const fallback = derived ? new DerivedKmsService(derived.secret) : null
    return fallback
      ? new FallbackKmsService(encedoPrimary, fallback)
      : encedoPrimary
  }

  // --- HashiCorp Vault (existing path) ---
  const primary = new HashicorpVaultKmsService()
  const derived = resolveDerivedKeySecret()
  const fallback = derived ? new DerivedKmsService(derived.secret) : null
  // ... (existing logic unchanged)
}
```

#### New Environment Variables

| Variable | Purpose |
|----------|---------|
| `ENCEDO_EPA_URL` | EPA REST endpoint (e.g. `https://epa.company.internal`) |
| `ENCEDO_EPA_TOKEN` | Bearer token or API key for EPA authentication |
| `ENCEDO_EPA_TTL_MS` | DEK cache TTL in milliseconds (default: 900000 = 15 min) |

When `ENCEDO_EPA_URL` is set, Encedo takes priority over HashiCorp Vault.  
Fallback chain remains: `EncedoEpaKmsService → DerivedKmsService → NoopKmsService`.

### 3.5 CLI Migration Command

A new CLI command should be added to the `entities` module for migrating existing Vault-stored DEKs
to Encedo:

```
mercato entities migrate-kms \
  --tenant <uuid> \
  --from vault \
  --to encedo \
  --dry-run
```

The command reads each DEK from the source KMS and writes it to the target KMS. No re-encryption of
AES-GCM ciphertext is needed because the raw DEK value is preserved — only the **key store** changes.

### 3.6 Backward Compatibility

Since `KmsService` is an internal interface (not part of the published module extension contract per
`BACKWARD_COMPATIBILITY.md`), adding `EncedoEpaKmsService` and extending `createKmsService()` is
non-breaking. Deployments without `ENCEDO_EPA_URL` continue to use HashiCorp Vault unchanged.

### 3.7 Security Considerations

- **Token rotation**: `ENCEDO_EPA_TOKEN` should be rotated periodically; EPA should support short-lived tokens
- **mTLS**: For production EPA deployments, mutual TLS is preferred over bearer tokens
- **PPA (USB variant)**: For the offline/personal variant, a separate `EncedoPpaKmsService` class would need a local USB/PKCS#11 bridge — out of scope for phase 1
- **Key never leaves hardware** (Option B): To fully leverage Encedo's HSM capability, the Phase 2
  envelope model (wrap/unwrap only, no raw key export) is required. In Option A, the raw DEK is
  returned by the EPA API and travels over HTTPS — secure in transit but weaker than the envelope model
- **Audit log**: Encedo EPA provides an immutable on-device audit log of all key access events —
  useful for GDPR compliance as evidence of who accessed DEKs and when

---

## 4. Summary

| Aspect | Current (HashiCorp Vault) | Proposed (Encedo EPA — Option A) |
|--------|--------------------------|----------------------------------|
| KMS type | Software-defined | Hardware-rooted HSM |
| Key storage | Vault KV secrets engine | Encedo EPA key store |
| Protocol | Vault HTTP API v1 | Encedo EPA REST API |
| Auth | Static `VAULT_TOKEN` | Bearer token / mTLS |
| Key never leaves hardware | No (Vault Enterprise + Seal only) | Yes (Option B only) |
| Latency | ~1–5 ms | ~0.5–2 ms (EPA) |
| Code change scope | 1 new file + factory extension | Minimal, backward compatible |
| Deployment complexity | Vault cluster required | EPA appliance or EPA cloud |
| Fallback chain | DerivedKmsService → NoopKmsService | Same (unchanged) |

The architecture of open-mercato is **well-prepared for KMS provider substitution**. The `KmsService`
interface is clean and narrow (3 methods). The `createKmsService()` factory is the single injection
point. An `EncedoEpaKmsService` implementation requires approximately **100–120 lines of TypeScript**
plus env-variable wiring, with zero changes to the encryption/decryption algorithms, ORM subscriber,
or CLI commands.

---

## 5. Testing Strategy for EncedoKmsService

### 5.1 Test Layers

The project uses two distinct test layers. Both matter for a KMS contribution:

| Layer | Tool | Location | Speed | Requires DB/network |
|-------|------|----------|-------|---------------------|
| Unit tests | Jest | `packages/shared/src/lib/encryption/__tests__/` | ~1 s | No |
| Integration tests | Playwright | `packages/<pkg>/src/modules/<mod>/__integration__/` | ~30–60 s | Yes (ephemeral Docker) |

For the Encedo KMS module, **unit tests are the primary contribution gate**. Integration tests
cover the end-to-end encryption flow and are required for PR approval but can be run in ephemeral
containers without any manual infrastructure.

---

### 5.2 Unit Tests — No Infra Required

Unit tests mock the HTTP layer entirely. The pattern used across the existing encryption tests is
**jest.fn() for DI containers, jest.mock() for module-level singletons**. No real database,
no real KMS endpoint needed.

#### 5.2.1 Running Unit Tests

```bash
# All unit tests (whole monorepo)
yarn test

# Only encryption-related tests
npx jest --testPathPattern="encryption"

# Only kms-encedo tests (once the file exists)
npx jest --testPathPattern="kms-encedo"

# Watch mode during active development
npx jest --watch --testPathPattern="kms-encedo"
```

#### 5.2.2 Unit Test File Location

```
packages/shared/src/lib/encryption/__tests__/kms-encedo.test.ts
```

#### 5.2.3 Reference Test Structure

Model tests after the existing pattern in
`packages/core/src/modules/entities/__tests__/cli-rotate-encryption.test.ts`
and `packages/shared/src/lib/encryption/__tests__/customFieldValues.test.ts`.

```typescript
/** @jest-environment node */
import { EncedoEpaKmsService } from '../kms-encedo'

// Minimal test DEK
const testDek = Buffer.alloc(32, 0xab).toString('base64')

describe('EncedoEpaKmsService', () => {
  let fetchSpy: jest.SpyInstance

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch')
  })

  afterEach(() => {
    fetchSpy.mockRestore()
  })

  describe('isHealthy()', () => {
    it('returns false when ENCEDO_EPA_URL is missing', () => {
      const svc = new EncedoEpaKmsService({ epaUrl: '', epaToken: 'tok' })
      expect(svc.isHealthy()).toBe(false)
    })

    it('returns false when ENCEDO_EPA_TOKEN is missing', () => {
      const svc = new EncedoEpaKmsService({ epaUrl: 'https://epa.local', epaToken: '' })
      expect(svc.isHealthy()).toBe(false)
    })

    it('returns true when both url and token are set', () => {
      const svc = new EncedoEpaKmsService({ epaUrl: 'https://epa.local', epaToken: 'tok' })
      expect(svc.isHealthy()).toBe(true)
    })
  })

  describe('getTenantDek()', () => {
    it('fetches DEK from EPA and returns TenantDek', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ key: testDek }),
      } as Response)

      const svc = new EncedoEpaKmsService({ epaUrl: 'https://epa.local', epaToken: 'tok' })
      const dek = await svc.getTenantDek('tenant-1')

      expect(dek).not.toBeNull()
      expect(dek!.tenantId).toBe('tenant-1')
      expect(dek!.key).toBe(testDek)
      expect(fetchSpy).toHaveBeenCalledWith(
        'https://epa.local/v1/keys/tenant_tenant-1',
        expect.objectContaining({ headers: { Authorization: 'Bearer tok' } }),
      )
    })

    it('returns cached DEK on second call without re-fetching', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true, status: 200,
        json: async () => ({ key: testDek }),
      } as Response)

      const svc = new EncedoEpaKmsService({ epaUrl: 'https://epa.local', epaToken: 'tok' })
      await svc.getTenantDek('tenant-1')
      await svc.getTenantDek('tenant-1')

      expect(fetchSpy).toHaveBeenCalledTimes(1)
    })

    it('returns null and marks unhealthy on 500', async () => {
      fetchSpy.mockResolvedValueOnce({ ok: false, status: 500 } as Response)

      const svc = new EncedoEpaKmsService({ epaUrl: 'https://epa.local', epaToken: 'tok' })
      const dek = await svc.getTenantDek('tenant-1')

      expect(dek).toBeNull()
      expect(svc.isHealthy()).toBe(false)
    })

    it('returns null (not unhealthy) on 404 — key not found', async () => {
      fetchSpy.mockResolvedValueOnce({ ok: false, status: 404 } as Response)

      const svc = new EncedoEpaKmsService({ epaUrl: 'https://epa.local', epaToken: 'tok' })
      const dek = await svc.getTenantDek('tenant-missing')

      expect(dek).toBeNull()
      expect(svc.isHealthy()).toBe(true)
    })
  })

  describe('createTenantDek()', () => {
    it('generates a new DEK and POSTs it to EPA', async () => {
      fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) } as Response)

      const svc = new EncedoEpaKmsService({ epaUrl: 'https://epa.local', epaToken: 'tok' })
      const dek = await svc.createTenantDek('tenant-new')

      expect(dek).not.toBeNull()
      expect(dek!.tenantId).toBe('tenant-new')
      expect(typeof dek!.key).toBe('string')
      expect(dek!.key.length).toBeGreaterThan(10)

      const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
      expect(url).toBe('https://epa.local/v1/keys/tenant_tenant-new')
      expect(init.method).toBe('POST')
      const body = JSON.parse(init.body as string) as { key: string }
      expect(body.key).toBe(dek!.key)
    })

    it('returns null on POST failure', async () => {
      fetchSpy.mockResolvedValueOnce({ ok: false, status: 403 } as Response)

      const svc = new EncedoEpaKmsService({ epaUrl: 'https://epa.local', epaToken: 'tok' })
      const dek = await svc.createTenantDek('tenant-new')
      expect(dek).toBeNull()
    })
  })

  describe('integration with createKmsService() factory', () => {
    it('uses EncedoEpaKmsService when ENCEDO_EPA_URL and ENCEDO_EPA_TOKEN are set', () => {
      process.env.TENANT_DATA_ENCRYPTION = 'yes'
      process.env.ENCEDO_EPA_URL = 'https://epa.local'
      process.env.ENCEDO_EPA_TOKEN = 'tok'
      delete process.env.VAULT_ADDR

      const { createKmsService } = require('../kms')
      const svc = createKmsService()

      // EncedoEpaKmsService (or FallbackKmsService wrapping it) should be active
      expect(svc.isHealthy()).toBe(true)

      delete process.env.ENCEDO_EPA_URL
      delete process.env.ENCEDO_EPA_TOKEN
      jest.resetModules()
    })
  })
})
```

**Key test cases to cover (minimum PR gate):**

| # | Scenario | Expected |
|---|----------|----------|
| 1 | Missing URL or token | `isHealthy() = false` |
| 2 | Successful GET key | returns correct `TenantDek` |
| 3 | In-memory cache hit | single HTTP call on two `getTenantDek` calls |
| 4 | Cache TTL expired | re-fetches after TTL |
| 5 | EPA returns 500 | `null`, marks unhealthy |
| 6 | EPA returns 404 | `null`, stays healthy |
| 7 | Successful POST new key | sends correct body, returns DEK |
| 8 | POST failure | `null` |
| 9 | FallbackKmsService wrapping | falls through to `DerivedKmsService` when EPA returns null |
| 10 | `createKmsService()` factory | picks `EncedoEpaKmsService` when env vars set |

---

### 5.3 Integration Tests — End-to-End with Mock EPA

Integration tests run against a real app instance in ephemeral Docker containers. For Encedo, the
strategy is to **mock the EPA HTTP endpoint** using a lightweight `mock-server` container (or
`nock` process-level interception), then exercise the full encryption pipeline through the API.

#### 5.3.1 Test Environment Setup

```bash
# Start ephemeral environment (Docker required, ~90 seconds first run)
yarn test:integration:ephemeral:start

# The running URL is written to .ai/qa/ephemeral-env.json
# Subsequent test runs reuse the same containers
yarn test:integration:ephemeral

# View HTML report
yarn test:integration:report
```

The ephemeral stack reads from `apps/mercato/.env.example`. To test Encedo path, override env vars:

```bash
# .env.test.local (or docker-compose override)
ENCEDO_EPA_URL=http://mock-epa:8300
ENCEDO_EPA_TOKEN=test-token
VAULT_ADDR=          # leave empty to disable Vault fallback
TENANT_DATA_ENCRYPTION=yes
TENANT_DATA_ENCRYPTION_FALLBACK_KEY=ci-test-fallback-32chars
```

#### 5.3.2 Mock EPA Server

Add a minimal Express/Node server in the integration test setup that implements the Encedo EPA
key storage contract:

```typescript
// packages/shared/src/lib/encryption/__tests__/mock-epa-server.ts
import http from 'node:http'

const store = new Map<string, string>()

export function startMockEpaServer(port = 8300): http.Server {
  const server = http.createServer((req, res) => {
    const key = req.url?.replace('/v1/keys/', '') ?? ''
    if (req.method === 'GET') {
      const value = store.get(key)
      if (!value) { res.writeHead(404); res.end('{}'); return }
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ key: value }))
    } else if (req.method === 'POST') {
      let body = ''
      req.on('data', (chunk) => { body += chunk })
      req.on('end', () => {
        const { key: k } = JSON.parse(body) as { key: string }
        store.set(key, k)
        res.writeHead(200); res.end('{}')
      })
    } else {
      res.writeHead(405); res.end()
    }
  })
  server.listen(port)
  return server
}
```

#### 5.3.3 Integration Test File Location and Pattern

```
packages/core/src/modules/entities/__integration__/encryption-encedo.spec.ts
```

```typescript
import { test, expect } from '@playwright/test'
import { getAuthToken, apiRequest } from '@open-mercato/core/helpers/integration/api'

test.describe('Encedo EPA KMS — field-level encryption', () => {
  let token: string

  test.beforeAll(async ({ request }) => {
    token = await getAuthToken(request, 'admin')
  })

  test('encrypted field is stored as ciphertext and returned as plaintext', async ({ request }) => {
    // Create a customer — email should be encrypted at rest via Encedo DEK
    const created = await apiRequest(request, 'POST', '/api/customers/entities', {
      token,
      data: { primaryEmail: 'test@encedo.example', displayName: 'Encedo Test' },
    })
    expect(created.ok()).toBe(true)
    const entity = await created.json() as { id: string; primaryEmail: string }

    // API returns plaintext (decrypted by ORM subscriber)
    expect(entity.primaryEmail).toBe('test@encedo.example')

    // Cleanup
    await apiRequest(request, 'DELETE', `/api/customers/entities/${entity.id}`, { token })
  })

  test('encryption map API sets fields and invalidates cache', async ({ request }) => {
    const mapRes = await apiRequest(request, 'GET', '/api/entities/encryption?entityId=auth:user', { token })
    expect(mapRes.ok()).toBe(true)
    const map = await mapRes.json() as { entityId: string; fields: unknown[] }
    expect(map.entityId).toBe('auth:user')
    // email field should be in the default map
    expect((map.fields as Array<{ field: string }>).some((f) => f.field === 'email')).toBe(true)
  })
})
```

---

### 5.4 Contribution Workflow

#### Fast iteration loop (recommended for active development)

```
1. yarn dev                          # Start Next.js dev server
2. npx jest --watch \
     --testPathPattern="kms-encedo"  # Unit tests in watch mode
3. Edit kms-encedo.ts
4. Tests auto-rerun → red → green
5. yarn lint                         # Check ESLint (no `any`, no unused imports)
6. yarn build:packages               # Verify TypeScript compiles across all packages
```

#### Pre-PR checklist

```bash
yarn test                            # All unit tests must pass
yarn lint                            # Zero ESLint errors
yarn build:packages                  # All packages build cleanly
yarn test:integration:ephemeral      # Integration tests green (Docker required)
```

#### PR scope for Phase 1 (MVP)

A minimal, mergeable PR for `EncedoEpaKmsService` should contain exactly:

| File | Change |
|------|--------|
| `packages/shared/src/lib/encryption/kms-encedo.ts` | New file — `EncedoEpaKmsService` class |
| `packages/shared/src/lib/encryption/kms.ts` | Extend `createKmsService()` factory (~15 lines) |
| `packages/shared/src/lib/encryption/__tests__/kms-encedo.test.ts` | Unit tests (10 cases minimum) |
| `apps/mercato/.env.example` | Add `ENCEDO_EPA_URL`, `ENCEDO_EPA_TOKEN`, `ENCEDO_EPA_TTL_MS` with comments |
| `packages/core/src/modules/entities/__integration__/encryption-encedo.spec.ts` | Integration smoke test |

No database migrations, no ORM changes, no CLI changes needed for Phase 1.

#### Branch and commit conventions

```bash
git checkout -b feat/encedo-kms-service

# Commits follow conventional commits:
git commit -m "feat(encryption): add EncedoEpaKmsService as KMS backend"
git commit -m "test(encryption): unit tests for EncedoEpaKmsService"
git commit -m "feat(encryption): wire EncedoEpaKmsService into createKmsService factory"
```

---

### 5.5 Debugging Tips

**Check which KMS backend is active:**

```bash
# Enable verbose encryption logging
TENANT_DATA_ENCRYPTION_DEBUG=true yarn dev

# You will see one of:
# 🔐 [encryption][kms] Hashicorp Vault KMS enabled
# ⚠️ [encryption][kms] Vault misconfigured → fallback to DerivedKmsService
# (with Encedo) 🔐 [encryption][kms] Encedo EPA KMS enabled   ← add this log to EncedoEpaKmsService
```

**Verify DEK is being fetched from Encedo (mock server logs):**

Start the mock EPA server with verbose logging that prints every `GET`/`POST`. Confirm that
`tenant_key_<uuid>` paths are being hit on first encrypt and served from in-process cache on repeat calls.

**Force cache bypass for testing:**

```typescript
// In test: create service with ttlMs = 0 to disable caching
const svc = new EncedoEpaKmsService({ epaUrl: '...', epaToken: '...', ttlMs: 0 })
```

**Check encryption state of a specific tenant via CLI:**

```bash
# Dry-run decrypt to verify fields are encrypted and can be decrypted with current KMS
ENCEDO_EPA_URL=https://epa.local \
ENCEDO_EPA_TOKEN=<token> \
npx mercato entities decrypt-database \
  --tenant <uuid> \
  --confirm <uuid> \
  --dry-run
```
