# Random-Crypto
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![arXiv:2506.02048](https://img.shields.io/badge/arXiv-2506.02048-b31b1b.svg)](https://arxiv.org/abs/2506.02048)

The Random-Crypto Benchmark provides a procedurally generated dataset of cryptographic CTF challenges, tailored for training and evaluating large language models in reinforcement learning settings.


---
## Dataset

* ✅ 50 Human-verified challenges for evaluation [(link)](https://github.com/aielte-research/Random-Crypto/tree/main/challenges/verified_challenges_50/all_challenges.csv)
* ⚙️ 5000 Non-Verified Challenges for training [(link)](https://github.com/aielte-research/Random-Crypto/tree/main/challenges/non_verified_challenges_5000/all_challenges.csv)

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

```.env
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
