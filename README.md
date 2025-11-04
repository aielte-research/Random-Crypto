# Random-Crypto
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![arXiv:2506.02048](https://img.shields.io/badge/arXiv-2506.02048-b31b1b.svg)](https://arxiv.org/abs/2506.02048)

The Random-Crypto Benchmark is a procedurally generated dataset of cryptographic CTF challenges. The benchmark was designed for reinforcement learning of LLM based agents. 

The benchmark's website can be visited [here](https://aielte-research.github.io/Random-Crypto/).


* ✅ 50 Human-verified challenges for evaluation [(link)](https://github.com/aielte-research/Random-Crypto/tree/main/challenges/verified_challenges_50/all_challenges.csv)
* ⚙️ 5000 Non-Verified Challenges for training [(link)](https://github.com/aielte-research/Random-Crypto/tree/main/challenges/non_verified_challenges_5000/all_challenges.csv)

---

## ⚙️ Generating New Challenges

**Set up the environment:**

```bash

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate 

# Install dependencies
pip install -r requirements.txt
```


Make sure to set your **OpenAI API key** in a `.env` file at the root of this folder:

```.env
OPENAI_API_KEY=your-key-here
```


### Example Usage
This code generates 50 challenges, one from each type.

```bash
python main.py --variants 1 --output_folder my_generated_challenges
```

This code generates 5000 challenges, one hundred from each type.

```bash
python main.py --variants 100 --output_folder my_generated_challenges
```

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
