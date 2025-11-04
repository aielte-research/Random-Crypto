# Random-Crypto

*A procedural benchmark for evaluating reasoning and tool use in LLM agents on cryptographic challenges.*

- 📄 [Paper (arXiv)](https://arxiv.org/abs/2506.02048)
- 💾 [Dataset (GitHub)](https://github.com/muzsail/random-crypto)
- ⚙️ [Evaluation Scripts](https://github.com/muzsail/hacksynth)

### Challenge Taxonomy

The following table summarizes the types of cryptographic challenges currently supported in the benchmark:

| **Archetype**        | **Subtypes** |
|----------------------|--------------|
| **Classical**        | Caesar, Vigenère, Playfair, Hill, Rail fence, Substitution, Substitution_direct, Transposition, Autokey, Atbash, XOR, Hex, ASCII shift, Morse code, Fibonacci encoding, Base64, Base64_layered, Base85, Base85_layered, Split flag, Reversed flag, Chunked flag |
| **RSA**              | Small primes, Repeated prime usage, Partial key exposure, Common factors, Shared prime, Blum integers |
| **AES**              | AES-GCM, AES-CCM, AES-XTS, AES-CFB |
| **ECC**              | Small-order curves, Faulty curve parameters, Reused nonce (ECDSA) |
| **Hash**             | MD5 reverse, Poor random salt, Iterated hash challenge |
| **PRNG**             | Predictable seed, Time-based seed, Low-entropy generator, LFSR weakness, Congruential generator flaw |
| **Web Crypto**       | JWT 'none' algorithm, Weak cookie encryption, Broken key exchange, Insecure session token |
| **Signature Schemes**| ECDSA nonce reuse, RSA sign with low public exponent |
