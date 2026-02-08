# JWT Signing Algorithm Benchmark Results

**Test Configuration:**
- Library: FusionAuth JWT v6.0.0
- Payload: Fixed JSON with exp, iat, iss, sub, applicationId, roles
- Iterations: 1000 measurements per algorithm (100 warmup)
- JVM: OpenJDK 17

---

## Signing Performance Rankings

| Rank | Algorithm | Key Size | Avg (µs) | Relative Speed |
|------|-----------|----------|----------|----------------|
| 1 | HS512 | 512 bits | 21.73 | 1.0x (baseline) |
| 2 | HS384 | 384 bits | 38.00 | 1.7x slower |
| 3 | HS256 | 256 bits | 54.05 | 2.5x slower |
| 4 | ES256 | 256 bits | 926.12 | 42.6x slower |
| 5 | Ed25519 | 25519 bits | 1,052.20 | 48.4x slower |
| 6 | PS512-2048 | 2048 bits | 1,318.09 | 60.6x slower |
| 7 | RS512-2048 | 2048 bits | 1,325.52 | 61.0x slower |
| 8 | RS384-2048 | 2048 bits | 1,327.49 | 61.1x slower |
| 9 | RS256-2048 | 2048 bits | 1,384.53 | 63.7x slower |
| 10 | PS256-2048 | 2048 bits | 1,389.76 | 63.9x slower |
| 11 | PS384-2048 | 2048 bits | 1,440.43 | 66.3x slower |
| 12 | RS384-3072 | 3072 bits | 4,022.49 | 185.1x slower |
| 13 | RS256-3072 | 3072 bits | 4,090.12 | 188.2x slower |
| 14 | RS512-3072 | 3072 bits | 4,302.66 | 198.0x slower |
| 15 | PS256-3072 | 3072 bits | 4,437.90 | 204.2x slower |
| 16 | PS384-3072 | 3072 bits | 4,457.39 | 205.1x slower |
| 17 | PS512-3072 | 3072 bits | 4,649.83 | 213.9x slower |
| 18 | RS512-4096 | 4096 bits | 10,435.40 | 480.2x slower |
| 19 | RS256-4096 | 4096 bits | 10,218.84 | 470.3x slower |
| 20 | PS256-4096 | 4096 bits | 10,898.79 | 501.6x slower |
| 21 | PS384-4096 | 4096 bits | 11,125.79 | 511.9x slower |
| 22 | RS384-4096 | 4096 bits | 11,237.08 | 517.1x slower |
| 23 | PS512-4096 | 4096 bits | 11,162.67 | 513.6x slower |
| 24 | ES384 | 384 bits | 2,025.48 | 93.2x slower |
| 25 | ES512 | 521 bits | 4,092.55 | 188.3x slower |

---

## Verification Performance Rankings

| Rank | Algorithm | Key Size | Avg (µs) | Relative Speed |
|------|-----------|----------|----------|----------------|
| 1 | HS512 | 512 bits | 17.89 | 1.0x (baseline) |
| 2 | HS384 | 384 bits | 31.56 | 1.8x slower |
| 3 | HS256 | 256 bits | 65.32 | 3.7x slower |
| 4 | PS512-2048 | 2048 bits | 66.43 | 3.7x slower |
| 5 | PS384-2048 | 2048 bits | 66.08 | 3.7x slower |
| 6 | PS256-2048 | 2048 bits | 68.06 | 3.8x slower |
| 7 | RS512-2048 | 2048 bits | 69.61 | 3.9x slower |
| 8 | RS384-2048 | 2048 bits | 70.22 | 3.9x slower |
| 9 | RS256-2048 | 2048 bits | 74.06 | 4.1x slower |
| 10 | RS512-3072 | 3072 bits | 125.50 | 7.0x slower |
| 11 | RS256-3072 | 3072 bits | 126.31 | 7.1x slower |
| 12 | RS384-3072 | 3072 bits | 127.53 | 7.1x slower |
| 13 | PS512-3072 | 3072 bits | 125.10 | 7.0x slower |
| 14 | PS256-3072 | 3072 bits | 130.46 | 7.3x slower |
| 15 | PS384-3072 | 3072 bits | 133.05 | 7.4x slower |
| 16 | RS384-4096 | 4096 bits | 212.86 | 11.9x slower |
| 17 | PS512-4096 | 4096 bits | 212.14 | 11.9x slower |
| 18 | PS384-4096 | 4096 bits | 214.27 | 12.0x slower |
| 19 | RS256-4096 | 4096 bits | 214.01 | 12.0x slower |
| 20 | PS256-4096 | 4096 bits | 233.04 | 13.0x slower |
| 21 | RS512-4096 | 4096 bits | 222.40 | 12.4x slower |
| 22 | Ed25519 | 25519 bits | 964.69 | 53.9x slower |
| 23 | ES256 | 256 bits | 1,601.58 | 89.5x slower |
| 24 | ES384 | 384 bits | 3,584.23 | 200.4x slower |
| 25 | ES512 | 521 bits | 6,651.79 | 371.8x slower |

---

## Key Insights

1. **HMAC dominates**: 17-514x faster than asymmetric algorithms for signing

2. **Verification is cheaper than signing**: RSA verification is 18-60x faster than signing. ECDSA verification is 1.7-2.1x slower than signing (asymmetric behavior)

3. **Key size impact**: Doubling RSA key size (2048→4096) increases signing time by ~8x but verification time only by ~3x

4. **RSA vs RSA-PSS**: Performance is nearly identical at each key size

5. **ECDSA curve impact**: Larger curves (P-384, P-521) significantly slower than P-256

6. **Ed25519 competitive**: Comparable to ES256 for signing, faster for verification than ECDSA curves

---

## Recommendations

- **High-throughput scenarios**: HS512 for symmetric needs, Ed25519 for asymmetric
- **Standard security**: RSA-2048 or Ed25519 balance performance/security
- **Long-lived tokens**: RSA-4096 for strong key longevity despite performance cost
- **Avoid**: ES512 for high-frequency verification use cases
