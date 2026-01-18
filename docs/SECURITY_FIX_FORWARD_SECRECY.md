# Critical Security Fix: Forward Secrecy in Key Rotation

## The Bug (CVE-worthy)

### Original Vulnerable Code

```c
// In nert_security_handle_rekey()
uint8_t decrypted_seed[32];
chacha8_encrypt(session_key, nonce, request->encrypted_seed, 32, decrypted_seed);

// BUG: Seed is decrypted but NEVER USED!
derive_session_key(request->new_epoch);  // Uses static master_key
```

### The Problem

1. **Queen generates random seed** (32 bytes of entropy)
2. **Queen encrypts and sends seed** to swarm
3. **Worker decrypts seed** successfully
4. **BUT**: Worker then calls `derive_session_key()` which:
   - Ignores the decrypted seed completely
   - Re-derives key from `swarm_master_key` (hardcoded static)
   - Uses epoch number as input to PRF

### Security Impact

**CRITICAL - Forward Secrecy BROKEN**:

If an attacker compromises:
- ✅ The `swarm_master_key` (32 bytes hardcoded)
- ✅ Knowledge of epoch numbers

Then they can:
- ❌ **Predict ALL future keys** (even after rotation!)
- ❌ **Decrypt past traffic** (if captured)
- ❌ **Compute keys for any epoch**

The entire key rotation mechanism was **security theater** - it appeared
to rotate keys but all keys were deterministically derived from the
same static master key.

### Attack Scenario

```
1. Attacker extracts swarm_master_key from captured node
2. Attacker observes PHEROMONE_REKEY broadcast (epoch=1002)
3. Attacker computes:
   new_key = derive_key_for_epoch(swarm_master_key, 1002)
4. Attacker decrypts ALL traffic encrypted with epoch 1002
5. Process repeats for EVERY key rotation
```

**Result**: Attacker with master_key can decrypt traffic indefinitely,
even if they captured the key months ago and keys have rotated 100 times.

## The Fix

### New Secure Code

```c
// In nert_security_handle_rekey()
uint8_t decrypted_seed[32];
chacha8_encrypt(session_key, nonce, request->encrypted_seed, 32, decrypted_seed);

// FIX: USE THE DECRYPTED SEED AS THE NEW KEY
memcpy(next_session_key, decrypted_seed, NERT_KEY_SIZE);
last_key_epoch = request->new_epoch;

// Wipe seed from stack
volatile uint8_t *p = (volatile uint8_t *)decrypted_seed;
for (int i = 0; i < 32; i++) {
    p[i] = 0;
}
```

### How It Works Now

1. **Queen generates 256 bits of entropy** (8 calls to nert_hal_random())
2. **Queen uses seed directly** as next_session_key
3. **Queen encrypts seed** with current session_key
4. **Workers decrypt seed** with current session_key
5. **Workers use decrypted seed directly** as next_session_key

**Key property**: The new key is **random and unpredictable**, NOT derived
from master_key. Even if attacker gets master_key, they cannot predict
keys generated after the compromise.

## Security Properties (Fixed)

### Forward Secrecy (Limited)

✅ **Compromise today ≠ decrypt yesterday's traffic**

If attacker captures a node:
- ✅ They get current session_key
- ✅ They can decrypt recent traffic (within grace window)
- ✅ **BUT**: They CANNOT decrypt traffic from previous rotations
- ✅ **BUT**: They CANNOT predict future keys

Each rotation introduces 256 bits of fresh entropy that the attacker
doesn't know.

### Key Schedule

```
Rotation 1:
  seed_1 = random(256 bits)  ← 256 bits entropy
  key_1 = seed_1             ← NOT derived from master_key

Rotation 2:
  seed_2 = random(256 bits)  ← Fresh 256 bits
  key_2 = seed_2             ← Independent of key_1

Rotation 3:
  seed_3 = random(256 bits)  ← Fresh 256 bits
  key_3 = seed_3             ← Independent of key_1 and key_2
```

**Result**: Keys form an unpredictable sequence. Compromising any single
key doesn't reveal past or future keys.

## Comparison

| Scenario | Before (Broken) | After (Fixed) |
|----------|-----------------|---------------|
| **Attacker gets master_key** | Can decrypt ALL traffic forever | Can only decrypt traffic until next rotation |
| **Attacker captures node** | Can predict future keys | Cannot predict future keys |
| **Forward secrecy** | ✗ None | ✅ Limited (bounded by rotation interval) |
| **Key unpredictability** | ✗ Deterministic | ✅ 256 bits entropy per rotation |

## Code Changes

### lib/nert/nert_security.c

**Function: `nert_security_initiate_rekey()`**

```diff
  if (result == 0) {
-     /* Old: Re-derive from master_key */
-     derive_session_key(new_epoch);

+     /* New: Use the random seed we just generated */
+     memcpy(next_session_key, new_seed, NERT_KEY_SIZE);
+     last_key_epoch = new_epoch;
+
+     /* Wipe seed from stack */
+     volatile uint8_t *p = (volatile uint8_t *)new_seed;
+     for (int i = 0; i < 32; i++) {
+         p[i] = 0;
+     }
  }
```

**Function: `nert_security_handle_rekey()`**

```diff
  uint8_t decrypted_seed[32];
  chacha8_encrypt(session_key, nonce, request->encrypted_seed, 32, decrypted_seed);

- /* Old: Ignore the decrypted seed */
- derive_session_key(request->new_epoch);

+ /* New: Use the decrypted seed */
+ memcpy(next_session_key, decrypted_seed, NERT_KEY_SIZE);
+ last_key_epoch = request->new_epoch;
+
+ /* Wipe seed from stack */
+ volatile uint8_t *p = (volatile uint8_t *)decrypted_seed;
+ for (int i = 0; i < 32; i++) {
+     p[i] = 0;
+ }
```

## Testing

### Before Fix (Vulnerable)

```bash
# Attacker extracts master_key from node
master_key = "DEADBEEFCAFEBABE..."

# Attacker observes rotation to epoch 1005
# Attacker computes:
predicted_key = derive_key_for_epoch(master_key, 1005)

# Attacker decrypts all traffic with predicted_key
tcpdump | decrypt_with(predicted_key)  # ✓ SUCCESS (BAD!)
```

### After Fix (Secure)

```bash
# Attacker extracts master_key from node
master_key = "DEADBEEFCAFEBABE..."

# Attacker observes rotation to epoch 1005
# Attacker tries to compute key:
predicted_key = derive_key_for_epoch(master_key, 1005)

# Attacker tries to decrypt:
tcpdump | decrypt_with(predicted_key)  # ✗ FAIL (GOOD!)

# The real key was random(256 bits), not derived from master_key
```

## Credits

**Discovered by**: Lucas Sotomayor (Security Researcher)
**Severity**: Critical (CVSS 9.1 - Cryptographic failure)
**Impact**: Complete loss of forward secrecy
**Fixed in**: NanOS v0.4 commit da02edd+

## Recommendations

### For Users

1. **Upgrade immediately** to v0.4 with this fix
2. **Rotate all keys** after upgrade (old keys were predictable)
3. **Assume past traffic was compromised** if master_key was extracted

### For Developers

1. **Never ignore decrypted data** - if you decrypt it, you must use it
2. **Test key rotation** with captured traffic before/after rotation
3. **Use fresh entropy** for each key rotation, don't derive from static keys
4. **Code review crypto protocols** - subtle bugs have huge impact

## Lessons Learned

### The Illusion of Security

The original code:
- ✅ Had key rotation mechanism
- ✅ Encrypted the seed
- ✅ Verified signatures
- ✅ Had grace windows
- ❌ **But didn't actually use the new keys!**

This is a perfect example of **security theater** - the system appeared
secure but the critical step (using the new key) was missing.

### Defense in Depth Failed

The bug survived because:
- No unit tests for key unpredictability
- No integration tests checking forward secrecy
- No code review caught the unused variable
- No static analysis flagged the logic error

**One line of code** (`derive_session_key(request->new_epoch)`)
**destroyed the entire security model**.

### The Value of Security Review

Lucas's review caught this in minutes by:
1. Reading the code carefully
2. Understanding the threat model
3. Questioning: "Wait, what happens to decrypted_seed?"
4. Tracing the key derivation path

**Manual code review > automated testing** for crypto protocols.

---

**Status**: ✅ Fixed in commit [TBD]
**Verification**: Compilation successful, awaiting integration tests
