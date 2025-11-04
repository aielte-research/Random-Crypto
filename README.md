# Random-Crypto
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![arXiv:2506.02048](https://img.shields.io/badge/arXiv-2506.02048-b31b1b.svg)](https://arxiv.org/abs/2506.02048)

The Random-Crypto Benchmark provides a procedurally generated dataset of cryptographic CTF challenges, tailored for training and evaluating large language models in reinforcement learning settings.


---
## Dataset

* ✅ 50 Human-verified challenges for evaluation [(link)](https://github.com/aielte-research/Random-Crypto/tree/main/challenges/verified_challenges_50/all_challenges.csv)
* ⚙️ 5000 Non-Verified Challenges for training [(link)](https://github.com/aielte-research/Random-Crypto/tree/main/challenges/non_verified_challenges_5000/all_challenges.csv)

> 🧠 **Note:** To evaluate an LLM using this benchmark, concatenate the `story` and `necessary_info` fields before passing them as input, the correct solution is in the flag column, if the LLM output contains the solution, it has solved the challenge.

---

## 📊 CSV Format

Each row in the challenge CSV files contains a single cryptographic task with the following columns:

- `story`: The main challenge description presented to the model.
- `necessary_info`: Key information required to solve the task.
- `hint`: (Optional) A short hint to help solve the challenge.
- `flag`: The expected correct solution (flag) in the format `flag{...}`.
- `cipher`: The type of cipher or cryptographic scheme used (e.g., Caesar, Vigenère).
- `extra_info`: Additional metadata, e.g., internal generation parameters or the used key.
- `difficulty`: One of `easy`, `medium`, or `hard`.

---

## ⚙️ Generating New Challenges

**1. Clone the repository:**
```bash
git clone [https://github.com/aielte-research/Random-Crypto.git](https://github.com/aielte-research/Random-Crypto.git)
cd Random-Crypto
```

**2. Set up the environment:**

```bash

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate 

# Install dependencies
pip install -r requirements.txt
```


If you want to generate new or additional procedural challenges, use the `main.py` script.

Make sure to set your **OpenAI API key** in a `.env` file at the root of this folder:

```env
OPENAI_API_KEY=your-key-here
```


### Example Usage
This code generates 100 challenges, two from each type.

```bash
python main.py --variants 2 --output_folder my_generated_challenges
```

This code generates 5000 challenges, one from each type.

```bash
python main.py --variants 100 --output_folder my_generated_challenges
```

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


---

## Contributors
- Lajos Muzsai (muzsailajos@protonmail.com)
- David Imolai (david@imol.ai)
- András Lukács (andras.lukacs@ttk.elte.hu)


## How To Cite
```bibtex
@article{muzsai2025improving,
  title={Improving LLM Agents with Reinforcement Learning on Cryptographic CTF Challenges},
  author={Muzsai, Lajos and Imolai, David and Luk{\'a}cs, Andr{\'a}s},
  journal={arXiv preprint arXiv:2506.02048},
  year={2025}
}
```
