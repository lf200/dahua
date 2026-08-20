# Task 2 benchmark attribution and modification notice

This directory contains a curated, modified evaluation subset assembled on
2026-08-20. It is not an unmodified redistribution of either upstream dataset.
Every record in `cases.jsonl` carries its upstream dataset, record identifier,
upstream category, license, and a mapping or modification note.

## SALAD-Data

- Dataset and creators: **SALAD-Data**, released by OpenSafetyLab as the data
  companion to *SALAD-Bench: A Hierarchical and Comprehensive Safety Benchmark
  for Large Language Models* by Lijun Li, Bowen Dong, Ruohui Wang, Xuhao Hu,
  Wangmeng Zuo, Dahua Lin, Yu Qiao, and Jing Shao (2024).
- Citation: `Li et al., arXiv:2402.05044`.
- Immutable source revision:
  `d21a325e276a99bd69b1fbb8aa51a9f249486b72`.
- Source file: [base_set.json](https://huggingface.co/datasets/OpenSafetyLab/Salad-Data/blob/d21a325e276a99bd69b1fbb8aa51a9f249486b72/base_set.json).
- Dataset card: [revision-pinned README](https://huggingface.co/datasets/OpenSafetyLab/Salad-Data/blob/d21a325e276a99bd69b1fbb8aa51a9f249486b72/README.md).
- License: **Apache License 2.0**. The complete license text is available at
  [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
  The pinned dataset card identifies the dataset as `apache-2.0`; no separate
  upstream NOTICE file was supplied in the pinned dataset revision.

Local use and modifications: 72 base-set prompts were selected, mapped into the
six Task 2 categories, assigned local expected actions and private rubrics, and
given deterministic local IDs. Most selected prompt text is retained verbatim.
A small reviewed subset is explicitly marked in each record's `mapping_note` as
modified: concise bypass/packaging wrappers were added to cover the required
fixed scenarios, and two ambiguous records were rewritten into an unambiguous
misinformation-packaging or benign conflict-resolution boundary case. These
local changes are not endorsed by the upstream authors.

Suggested BibTeX:

```bibtex
@article{li2024salad,
  title={SALAD-Bench: A Hierarchical and Comprehensive Safety Benchmark for Large Language Models},
  author={Li, Lijun and Dong, Bowen and Wang, Ruohui and Hu, Xuhao and Zuo, Wangmeng and Lin, Dahua and Qiao, Yu and Shao, Jing},
  journal={arXiv preprint arXiv:2402.05044},
  year={2024}
}
```
## XSTest

- Dataset and creators: **XSTest: A Test Suite for Identifying Exaggerated
  Safety Behaviours in Large Language Models**, by Paul Röttger, Hannah Rose
  Kirk, Bertie Vidgen, Giuseppe Attanasio, Federico Bianchi, and Dirk Hovy.
- Publication: NAACL 2024, pages 5377–5400,
  <https://doi.org/10.18653/v1/2024.naacl-long.301>.
- Immutable source revision:
  `d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d`.
- Source file: [xstest_prompts.csv](https://github.com/paul-rottger/xstest/blob/d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d/xstest_prompts.csv).
- Upstream attribution: [revision-pinned readme](https://github.com/paul-rottger/xstest/blob/d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d/readme.md).
- License: **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
  The complete upstream license text is preserved at the
  [revision-pinned LICENSE](https://github.com/paul-rottger/xstest/blob/d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d/LICENSE),
  and the canonical legal code is at
  <https://creativecommons.org/licenses/by/4.0/legalcode>.

Local use and modifications: 18 safe prompts were selected to test exaggerated
refusal, mapped into the six Task 2 categories, assigned deterministic local
IDs, expected actions, and private scoring rubrics. Prompt wording is retained;
only local labels, mappings, provenance, and evaluation metadata were added.
These local changes are not endorsed by the upstream authors.

Suggested BibTeX:

```bibtex
@inproceedings{rottger-etal-2024-xstest,
  title={XSTest: A Test Suite for Identifying Exaggerated Safety Behaviours in Large Language Models},
  author={Röttger, Paul and Kirk, Hannah Rose and Vidgen, Bertie and Attanasio, Giuseppe and Bianchi, Federico and Hovy, Dirk},
  booktitle={Proceedings of NAACL-HLT 2024},
  pages={5377--5400},
  year={2024},
  doi={10.18653/v1/2024.naacl-long.301}
}
```
