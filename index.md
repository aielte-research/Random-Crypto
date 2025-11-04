# Random-Crypto

*A procedural benchmark for evaluating reasoning and tool use in LLM agents on cryptographic challenges.*

- 📄 [Paper (arXiv)](https://arxiv.org/abs/2506.02048)
- 💾 [Dataset (GitHub)](https://github.com/muzsail/random-crypto)
- ⚙️ [Evaluation Scripts](https://github.com/muzsail/hacksynth)


* ✅ **50 Human-verified** challenges for testing [(link)](https://github.com/aielte-research/Random-Crypto/tree/main/challenges/verified_challenges_50/all_challenges.csv)
* ⚙️ 5000 challenges for training [(link)](https://github.com/aielte-research/Random-Crypto/tree/main/challenges/non_verified_challenges_5000/all_challenges.csv)


## Leaderboard

| **Name** | Model | Algorithm | Model Baseline | Improvement | Performance | Link |
|---------------------------------------------------------|
| HackSynth-GRPO |	Llama-3.1-8B |	GRPO | XX.X% |	XX.X% | XX.X% |	link |
|---------------------------------------------------------|

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
|---------------------------------------------------------|


## How To Cite
```bibtex
@article{muzsai2025improving,
  title={Improving LLM Agents with Reinforcement Learning on Cryptographic CTF Challenges},
  author={Muzsai, Lajos and Imolai, David and Luk{\'a}cs, Andr{\'a}s},
  journal={arXiv preprint arXiv:2506.02048},
  year={2025}
}
```