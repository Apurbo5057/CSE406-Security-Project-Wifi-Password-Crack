# CSE406 Project 20 — Wi-Fi Password Cracking Attack
## Research + Sessional Strategy

---

## 1. Executive Summary

A research-grade Project 20 is realistic, but only along one axis: **candidate-generation efficiency and its evaluation under WPA2's real verification cost**, not "add an LLM to Wi-Fi hacking." The literature search below turned up a specific, checkable fact that should anchor the whole project: a 2025 empirical study found that general-purpose LLMs (TinyLlama, Falcon-RW-1B, Flan-T5), even given rich contextual prompts, achieve **under 1.5% Hit@10** on password guessing, while simple rule-based/combinator methods hit **~33% Hit@10** on the same benchmark (Rehman et al., 2025, arXiv:2510.17884). Meanwhile fine-tuned, domain-specific generative models — PassGPT, PagPassGPT, PassBERT, PassLLM, KAPG — do meaningfully beat classical PCFG/Markov baselines (Rando et al. 2023; KAPG, arXiv:2510.23036, reports ~36.5% improvement over OMEN/PCFG at a 10^25-guess budget). So: raw LLM-as-password-generator is a dead end (good, checkable, citable negative result); fine-tuned/hybrid generative models are a live area; and **none of this literature is evaluated against WPA2's actual verification cost**, which is the gap this project exploits.

**The recommended direction (Option B below):** build the required WPA2 handshake-capture-and-crack tool yourselves, but replace "brute force / static wordlist" with a **cost-aware candidate-ranking pipeline** — benchmarking classical (PCFG, OMEN/Markov) against a fine-tuned small generative model, under the *actual* WPA2 PBKDF2-HMAC-SHA1 verification cost (thousands, not billions, of guesses/sec), using a passphrase corpus you construct that separates **human-chosen** from **router-default-generated** Wi-Fi passphrases. The defense bonus is earned by turning the same candidate model into a **guessability estimator** at router setup — the standard "attacker model becomes defender's proactive checker" pattern (Melicher et al. 2016 FLA; Pasquini et al. 2020 interpretable meters), applied to a domain (Wi-Fi PSKs) that hasn't been done this way.

This keeps 100% course compliance (you write the packet-crafting, deauth, handshake parsing, and PBKDF2/PMK/PTK/MIC verification yourself — no aircrack/hashcat as the graded tool), gives you a strong Design/Final report narrative, and produces a paper-shaped contribution even though it's realistically a **workshop-tier** paper, not a top-4 venue — see Section 20.

---

## 2. Project 20 Requirements (extracted constraints)

- **Must implement your own attack tool.** Frame/packet crafting (deauth frames, EAPOL capture/parsing), key derivation (PBKDF2→PMK→PTK→MIC), and guess verification must be your code. Existing tools (aircrack-ng, hashcat, Reaver) are reference/validation only, not the graded artifact.
- **Frameworks/pretrained models allowed as environment**, not as the attack itself — e.g., you may use NumPy/PyTorch for a candidate-ranking model, but the packet-level and cryptographic attack logic must be yours.
- **Reproducibility required**: pinned models, datasets, and random seeds — this pushes you toward a documented experimental pipeline rather than an ad hoc demo.
- **Grading**: Design Report 20%, Implementation+Demo 60%, Final Report 20%, **+10% bonus for a defense mechanism**.
- **Design report** needs: attack definition/topology, timing diagrams (before/after attack), packet/frame details and modifications, justification of why it works.
- **Final report/demo** needs: attack procedure, attacker/victim/AP-side observations, success/failure analysis, countermeasure design.
- **To maximize the 60%**: a clean, reliably reproducible end-to-end demo (capture → derive → verify → recovered passphrase) matters more than raw guess throughput. Graders are watching you *demonstrate* the mechanism, not watching a GPU cluster.
- **To get the +10%**: the defense must be something you *implement*, not just describe — a working detector, a working PMF/802.11w mitigation, or a working proactive-strength checker with measurable effect.

---

## 3. Conventional Baseline Project ("what would a normal student do")

Environment: your own home AP (WPA2-Personal, AES-CCMP), attacker laptop with a monitor-mode-capable adapter, victim client device — all under your control, closed lab.

Pipeline:
1. Monitor-mode capture (yourself, via raw 802.11 frame injection/parsing — e.g., scapy or raw sockets) of beacon/probe frames to identify BSSID/SSID/channel.
2. Craft and send deauthentication frames (spoofing the AP's source address) to force a client to re-associate, exposing the 4-way EAPOL handshake — or capture a PMKID from the first EAPOL frame (RSN IE) if the AP is vulnerable, avoiding the need for a connected client at all (Steube's PMKID technique).
3. Parse the 4 EAPOL frames; extract ANonce, SNonce, MIC, and the relevant MAC addresses.
4. For each candidate password: PBKDF2-HMAC-SHA1(password, SSID, 4096 iterations) → PMK → PTK (via PRF with ANonce/SNonce/MACs) → compute MIC over EAPOL frame 2 → compare to captured MIC.
5. Iterate over a static wordlist (rockyou.txt-style) until match, or fail.
6. Report cracking time, guesses/sec, and success/failure.

**Why this is insufficient for a research paper:** it is a reimplementation of aircrack-ng's core loop with no new question attached. "We wrote our own version of a well-known attack" satisfies the course but has zero novelty — every group doing Project 20 will submit some variant of this. There is no baseline-vs-alternative comparison, no metric beyond "did it crack, how long," and no defense that isn't already a standard textbook recommendation (PMF, long passphrases). This is Option A below, not a paper.

---

## 4. Research Landscape (2022–2026, with foundational anchors)

**Classical / structural models** (foundational, still the working baselines):
- Weir et al. (2009) — PCFG-based password cracking; the standard structural baseline.
- Dürmuth et al. (2015) — OMEN, ordered Markov enumerator; still cited as SOTA-classical.
- Bonneau (2012) — guesswork/α-work-factor metrics from 70M Yahoo passwords; the standard way to *measure* guessing efficiency, not just accuracy.

**Neural / generative models** (the active research area):
- Melicher et al. (2016, USENIX Sec) — FLA, LSTM-based guessability model, light enough for client-side use; also the ancestor of "guessing model as defensive strength meter."
- Hitaj et al. (2019) — PassGAN, GAN-based generation, beat rule-based tools on unseen variants.
- Pasquini et al. (2021, 2024 IEEE S&P) — representation learning for guessing, and **Universal Neural-Cracking-Machines**, a self-configurable model from auxiliary data (arXiv:2301.07628) — directly relevant to the "context-aware" question in Part 4 below.
- Rando et al. (2023) — PassGPT, GPT-based password modeling/guided generation (arXiv:2306.01545).
- PagPassGPT (2024, arXiv:2404.04886) — pattern-guided GPT generation, +12% hit rate over prior SOTA via structural conditioning.
- Wang et al. (2024) — PassTSL, two-stage learning (arXiv:2407.14145).
- **KAPG** (2025, arXiv:2510.23036) — knowledge-augmented, retrieval-style generation that injects external lexical trends into a Markov generator; **+36.5% over OMEN/PCFG/CKL-PCFG at 10^25 guesses** on 12 leaked datasets. This is your strongest recent non-LLM-heavy baseline to beat/compare against.
- **MAYA** (2025, arXiv:2504.16651) — a unified benchmark exposing inconsistent evaluation protocols across generative password-guessing papers; useful for you to borrow a *rigorous* evaluation methodology rather than inventing your own ad hoc one.
- Feature-guided diffusion password guessing (Eng. Proc. 2025, ICKII) — very recent (Aug 2025), diffusion model conditioned on masked-character features; ambitious/less battle-tested (this is your Option C candidate).

**LLM-specific, with a clear negative result:**
- Pavur & Angelopoulos (2023) — GPT-3 for password cracking; concluded LLMs overgeneralize, lack deterministic precision.
- **Rehman et al. (2025, arXiv:2510.17884)** — "When Intelligence Fails": rigorous Hit@k benchmark, zero-shot open LLMs vs 5 classical baselines over 20,000 synthetic profiles. LLMs: <1.5% Hit@10, 0% on hashed matches. Rule-based: 33% Hit@10. **This is your citation for "don't force an LLM in."**
- PassLLM (LoRA fine-tuned Llama/Mistral/Qwen on RockYou) and PassBERT — cited in a 2026 prompt-evolution paper (arXiv:2604.12601) as beating prior methods on trawling/PII/reuse attacks — i.e., fine-tuned, domain-adapted LLMs *can* work; zero-shot general ones don't.

**Wi-Fi/WPA2-specific literature — genuinely thin, and that thinness is your gap:**
- Lorente et al. (2015, USENIX WOOT) — "Scrutinizing WPA2 Password Generating Algorithms in Wireless Routers": many routers derive default PSKs from serial number/MAC via weak, reverse-engineerable algorithms. Establishes that **a large fraction of real-world WPA2 passphrases are not human-chosen at all** — they're router-generated, and their guessability follows completely different rules than human-chosen ones.
- "A Method for Cracking WPA2-PSK Based on SA and HMM" (IEEE, 2016) — the only prior work found that adapts a probabilistic generative model (simulated annealing + HMM) specifically to WPA2-PSK candidate generation. It predates every modern neural/LLM-based guesser above by nearly a decade and used a comparatively primitive model.
- "A large-scale analysis of Wi-Fi passwords" (2022) — large anonymized Wi-Fi password corpus study exists, but is not integrated with any of the 2023–2025 generative guessing models above.
- No paper found (as of this search) benchmarks a modern generative guesser (KAPG/PagPassGPT/PassGPT-class) against the **actual WPA2 PBKDF2 verification cost** — every Hit@k number in the generative-guessing literature above is computed against cheap/unsalted hash comparisons (or plaintext matching), which silently assumes an attacker can test billions of guesses/sec. Under real WPA2 PBKDF2 (4096 SHA1 rounds, ~tens of thousands of guesses/sec on a strong GPU, far slower than MD5/SHA1/bcrypt-lite benchmarks used elsewhere), the *value of getting to the true password in fewer guesses* changes by orders of magnitude relative to a cheap-hash setting. This is checkable, quantifiable, and nobody has published it for the current generation of guessers.

---

## 5. Research Gaps — skeptical assessment

**A. What's already done:** classical structural/statistical guessing (PCFG, OMEN) — saturated. Neural sequence models (LSTM/GAN/GPT) for web-leak-style passwords — active but crowded, many incremental %-improvement papers. "LLM can't zero-shot guess passwords" — now empirically established (2025), don't re-litigate it as a "finding," cite it as a premise.

**B. Obvious/saturated ideas to avoid:** "train a GPT on RockYou and report perplexity/Hit@k" (done many times); "LLM writes a wordlist" (empirically debunked, not a contribution); "use aircrack-ng faster with more GPUs" (engineering, not research); "propose yet another neural architecture that beats PCFG by 3% on RockYou" (real but low-novelty, incremental).

**C. Meaningful, still-open gaps:**
1. Generative guessing model evaluation under an *expensive* verification oracle (WPA2 PBKDF2) rather than cheap-hash Hit@k — a methodological gap, not just "yet another model."
2. A constructed, ethically-sourced Wi-Fi-passphrase corpus that separates human-chosen vs router-default passphrases, and a measurement of whether web-leak-trained guessers transfer to the human-chosen subset at all.
3. Turning a guessing model into a **real-time, on-router guessability/strength estimator** specifically calibrated to Wi-Fi's threat model (offline, attacker-controlled compute, PBKDF2 cost) rather than reusing a generic web-password strength meter.

**D. Realistically solvable by a student team in ~6 months:** #1 and #3 above, cleanly. #2 (a real corpus) is solvable only in a reduced/synthetic form (see Section 16 — real leaked Wi-Fi passphrase corpora at scale essentially don't exist publicly, for good reason; you will need self-generated/synthetic + the router-default-algorithm angle from Lorente et al.).

**E. Which could be a real contribution vs a benchmark:** #1 is a genuine contribution if done rigorously (it changes how the field should report Hit@k for this application; it's not just another leaderboard entry). #3 is a solid engineering + evaluation contribution (measurable false-negative rate: how many actually-weak PSKs would your checker have flagged). #2 is valuable groundwork but, alone, is a dataset paper, not a mechanism paper — pair it with #1.

---

## 6. AI/ML/LLM Opportunities — explicit verdicts

| Direction | Verdict | Why |
|---|---|---|
| Raw/zero-shot LLM generates password guesses | **Reject** | Empirically debunked (arXiv:2510.17884): <1.5% Hit@10 vs 33% for rule-based. Would be citing evidence against your own approach. |
| Fine-tuned small LM / hybrid classical+neural candidate ranker | **Adopt (core of Option B)** | KAPG, PagPassGPT, PassGPT show real, measurable gains over PCFG/OMEN when *trained on password structure specifically*, not natural language. |
| Context-aware guessing using SSID/public metadata | **Adopt, narrow scope** | Personal-PCFG (Li et al. 2016) shows personal-info-conditioned grammars measurably help; SSID is the one piece of context genuinely public and observable pre-attack in the Wi-Fi setting (unlike a target's birthdate). Must stay in your own controlled SSIDs — no scanning real neighborhood networks. |
| Adaptive/active-learning/bandit search that updates on failed guesses | **Reject for this attack surface** | WPA2 offline cracking gives the attacker unlimited, free, local verification once the handshake is captured — there is no "failure signal" to adapt from beyond "not this guess," which classical rank-ordering already exploits optimally. Adaptive/bandit methods earn their keep in *rate-limited online* guessing (e.g., a login form with lockouts), which is a different attack surface than what Project 20 specifies. Flagging this explicitly rather than forcing it in. |
| Defense-oriented ML: detect the attack | **Partially reject, partially adopt** | The *offline cracking phase* is undetectable by the AP by construction (attacker never touches the network again after handshake capture) — don't propose "ML detects password cracking in progress," it's not physically observable. What *is* detectable and worth building: the **deauthentication precursor** (an ML/statistical WIDS-style detector for abnormal deauth bursts) — but 802.11w/PMF already solves this deterministically, so an ML detector adds little beyond what a protocol fix does. The stronger defense-bonus play is proactive (#3 below). |
| Guessability estimator / proactive strength checker built from your own candidate model | **Adopt (defense bonus)** | Directly reuses your attack model, gives a working, demoable, measurable defense component, and matches an established, defensible research pattern (Melicher et al. FLA; Pasquini et al. interpretable meters) that hasn't been instantiated for Wi-Fi PSKs specifically. |
| Adversarial/game-theoretic attacker-defender formulation | **Reject as primary angle, mention as future work** | Interesting in principle but adds significant formalism/scope for a 6-month sessional without clear payoff; the literature search didn't surface a clean way to instantiate it for *offline* WPA2 cracking specifically (game-theoretic framings fit online/rate-limited settings better). |

---

## 7. Candidate Research Directions (ranked)

| # | Direction | Novelty | CSE406 fit | Defense bonus | Risk | Verdict |
|---|---|---|---|---|---|---|
| 1 | **Cost-aware candidate ranking under real WPA2 PBKDF2 oracle + guessability-estimator defense** | Medium-high (methodological gap, clearly evidenced above) | Excellent | Built-in | Medium | **Recommended (Option B)** |
| 2 | Baseline: own attack tool + PCFG/OMEN wordlist ranking + PMF/802.11w defense | Low | Excellent | Yes (protocol-level) | Low | **Recommended (Option A — safety net)** |
| 3 | SSID-conditioned diffusion-model candidate generator (adapting the 2025 feature-guided diffusion paper) | High | Good, if attack tool still self-implemented | Possible | High (very new method, hard to reproduce well in-semester) | **Recommended (Option C — stretch)** |
| 4 | Raw LLM prompted with network metadata to generate guesses | None (debunked) | OK | No natural tie-in | Low effort, zero payoff | Reject |
| 5 | ML-based deauth/WIDS anomaly detector as standalone project | Low-medium (well-trodden IDS space) | Good | Yes | Low | Fallback defense module only, not a standalone paper |
| 6 | Bandit/RL adaptive guessing against WPA2 | Low fit (wrong threat model, argued above) | Weak justification | No | High (conceptually mismatched) | Reject |
| 7 | Federated/privacy-preserving password model training | Interesting but orthogonal to Wi-Fi-specific gap | Weak | No | Medium | Reject (out of scope) |
| 8 | Attacker-defender game-theoretic formulation | Underdeveloped for offline setting | Weak | Theoretical only | High | Reject as primary |

---

## 8. Recommended Project (Option B, primary)

**System architecture**

```
[Course-required components]                    [Research contribution]
 ├─ 802.11 monitor-mode capture (own code)
 ├─ Deauth frame crafting / PMKID capture
 ├─ EAPOL 4-way handshake parser
 ├─ PBKDF2→PMK→PTK→MIC verification (own code)
 │                                          ──►  Candidate Ranking Module
 │                                                 ├─ Baseline: PCFG (Weir et al.)
 │                                                 ├─ Baseline: OMEN (Markov)
 │                                                 └─ Proposed: small fine-tuned LM /
 │                                                    hybrid ranker, SSID-conditioned
 │                                          ◄──  ranked guess stream, consumed by
 │                                                the verification loop above
 ├─ Guess-loop driver + timing/guess-count logger
 └─ Attack demo (against your own AP)
                                                  Defense Module (bonus)
                                                   ├─ Guessability Estimator
                                                   │   (reuses ranking module,
                                                   │    scores a candidate PSK
                                                   │    by expected-guesses-to-crack
                                                   │    under the real PBKDF2 cost)
                                                   └─ Router-setup-time checker:
                                                       accept/reject PSK + suggested
                                                       stronger alternative
```

Course-required vs research-contribution split is explicit: the packet/crypto pipeline is 100% yours and satisfies the "implement the attack yourself" rule regardless of which candidate-ranking method feeds it. The ranking module is swappable — that's what makes the ablations in Section 18 possible.

---

## 9. Exact Research Question / Contribution

> Existing generative password-guessing models (PCFG, OMEN, KAPG, PagPassGPT-class) are evaluated almost exclusively against cheap or unsalted hash comparisons, implicitly assuming near-free per-guess verification. WPA2-PSK verification is not free (PBKDF2-HMAC-SHA1, 4096 rounds, SSID-salted). **We show that guess-ranking quality (measured in guesses-to-crack) matters more, not less, under an expensive oracle, and we quantify how much wall-clock cracking time a strong ranker saves versus a naive dictionary/brute-force baseline on a self-collected Wi-Fi passphrase corpus that separates human-chosen from router-default PSKs.** We then repurpose the same ranking model as a real-time guessability estimator that a router can run at setup time to reject weak PSKs before they're ever deployed.

- **Primary contribution:** empirical, wall-clock-grounded comparison of candidate-ranking strategies under a genuinely expensive verification oracle — a measurement the existing generative-guessing literature doesn't provide.
- **Secondary contribution:** a small, ethically-collected Wi-Fi passphrase corpus (human-chosen vs router-default subsets) and evidence (or refutation) of whether web-leak-trained models transfer to it.
- **Engineering contribution:** a from-scratch, correct implementation of the WPA2 4-way handshake capture/crack pipeline (satisfies course requirement, independently useful).
- **Defense contribution:** a proactive guessability estimator usable at router-configuration time, with measured false-negative rate against your corpus.
- **Experimental contribution:** an ablation-driven demonstration that the improvement is attributable to the ranking model and not to dataset leakage or evaluation artifacts (see Section 18 — this directly answers MAYA's (2025) critique that the field's evaluations are often inconsistent).

Explicitly avoided vague contributions: not "we use AI," not "we improve accuracy" — the claim is about **guesses-to-crack under a specific, realistic cost model**, which is falsifiable and measurable.

---

## 10. Attack Implementation Plan

1. **Weeks 1–3:** monitor-mode capture, deauth/PMKID capture, EAPOL parsing — validate against aircrack-ng output on your own AP (aircrack-ng used only to *check* correctness, never as the graded tool).
2. **Weeks 3–5:** own PBKDF2→PMK→PTK→MIC verification loop; correctness-check against a known password/handshake pair.
3. **Weeks 4–6:** implement PCFG and OMEN baselines (both have published algorithms; OMEN's ordered-enumeration approach and PCFG's grammar approach are well-documented, implement from the papers, don't import ready cracking-suite code as the graded logic).
4. **Weeks 6–9:** collect/construct the passphrase corpus (Section 16); fine-tune or adapt a small generative ranker (a small char-level LM is enough — do not reach for a multi-billion-parameter LLM, both because of the negative LLM result in Section 6 and because inference cost would dominate your guess budget).
5. **Weeks 9–11:** integrate ranker into the guess loop; run the cost-aware evaluation (Section 15/17).
6. **Weeks 9–12 (parallel):** build the guessability-estimator defense and the router-setup-time check.

---

## 11. Defense Design (bonus)

**Primary defense — Guessability Estimator:**
- Input: a candidate PSK the user is about to set.
- Runs your ranking model in reverse: estimates the candidate's rank in the guess order (or an interpolated guesses-to-crack figure), scaled by your measured WPA2-PBKDF2 guesses/sec on your test hardware.
- Output: accept / reject-with-reason / suggested stronger alternative (e.g., append entropy, or, per the router-default-algorithm literature, warn if the passphrase pattern resembles a known-weak router-default scheme).
- Measurable: run it against your corpus's known-weak PSKs and known-strong (random 16+ char) PSKs; report false-negative rate (weak PSKs it fails to flag) and false-positive rate (strong PSKs it wrongly flags).

**Secondary/fallback defense (cheap, if time runs short):** implement 802.11w/PMF support-check and a deauth-burst detector (simple statistical threshold, not necessarily ML) as a documented mitigation for the handshake-capture precursor step. This alone satisfies "implemented a defense mechanism" even if the estimator above slips.

---

## 12. Experimental Protocol

- **Baselines:** PCFG (Weir et al.), OMEN (Dürmuth et al.), naive dictionary/brute-force (the "normal student" baseline from Section 3).
- **Proposed:** small fine-tuned generative ranker, optionally SSID-conditioned.
- **Oracle cost model:** measured guesses/sec of your own PBKDF2-HMAC-SHA1 implementation on your actual hardware (report both CPU and, if available, GPU-accelerated numbers) — this is what turns Hit@k into wall-clock time, the whole point of the contribution.
- **Splits:** human-chosen vs router-default subsets of your corpus, evaluated separately (this is where the "does web-leak training transfer" question gets answered).

---

## 13. Datasets

- **Public leaked web-password corpora** (RockYou-class) for training/pretraining the ranker's language of "human password structure" — standard, ethically established practice in this literature (used by every paper cited above).
- **Self-constructed Wi-Fi passphrase set:** a modest number (aim for order-of-hundreds, not millions — be honest about scale in the report) of PSKs you and consenting classmates/friends set on test APs specifically for this project, explicitly labeled as synthetic/lab-only, **never real production networks you don't own**. Pair with router-default PSKs generated by the algorithms described in Lorente et al. (2015) to build the "router-default" subset without needing any real captured traffic.
- Do **not** attempt to scrape or capture real neighborhood Wi-Fi handshakes — stay inside Part 14's ethics boundary.

---

## 14. Baselines (repeated for clarity, evaluation section)
PCFG, OMEN, naive/dictionary brute force — all three already required for the ablations below and directly comparable in the literature, so your numbers are externally sanity-checkable.

---

## 15. Evaluation Metrics
- Guesses-to-crack (median, and full guesswork curve, per Bonneau 2012's methodology).
- **Wall-clock time-to-crack**, using your measured PBKDF2 guesses/sec — the metric that doesn't exist yet in this form in the literature.
- Top-k / Hit@k for direct comparability with prior papers.
- Guessability-estimator: false-negative / false-positive rate, and correlation between estimated and actual guesses-to-crack.
- Computational cost of the ranking model itself (must stay small relative to per-guess PBKDF2 cost or it defeats the point).

---

## 16. Ablation Studies
- PCFG alone / OMEN alone / proposed ranker alone / hybrid.
- With vs without SSID conditioning.
- Human-chosen subset vs router-default subset (does the ranker's advantage hold on both, or only one — expect it to hold mainly on the human-chosen subset, and say so if that's what you find; a negative result on the router-default subset is itself informative, not a failure).
- Cheap-hash cost model (replicating prior papers' assumption) vs your real PBKDF2 cost model — this is the ablation that directly demonstrates your contribution's reason for existing.

---

## 17. Publication Venue Strategy

Be realistic, not aspirational:

- **USENIX Security / IEEE S&P / ACM CCS / NDSS:** not realistic as a first target. These require larger-scale evaluation, stronger threat novelty, and a track record; the recommended project's contribution (a measurement + a defense recipe) is real but not top-tier-scale.
- **WOOT (USENIX Workshop on Offensive Technologies):** a good realistic fit in spirit — it's exactly the venue that published the router-default-PSK paper this project builds on — but competitive; treat as an aspirational stretch after a workshop-level version is solid.
- **Regional/national security or networking workshops, and university/departmental symposia:** the realistic first target for an undergraduate sessional-derived paper. Check for a BUET-affiliated or South/Southeast-Asian regional security workshop, or a general-purpose CS undergraduate research symposium.
- **Password/authentication-specific workshops** (attached to larger security conferences, e.g., a "who-are-you" or usable-security-adjacent workshop) — worth watching for open calls, they're the natural community for this specific contribution.
- **Journal option later:** if the corpus and evaluation are extended in a follow-up (e.g., thesis-scale project), a mid-tier security/networking journal is a plausible target for an expanded version — not for the sessional-scale result alone.

Do not promise publication. The realistic claim to make to yourselves: "workshop/symposium-shaped contribution, publishable with meaningful extension effort beyond the sessional."

---

## 18. Six-Month Roadmap

- **Month 1:** literature review consolidation (this document + primary sources), threat model write-up, own-AP lab setup, start of monitor-mode capture code.
- **Month 2:** deauth/PMKID capture working end-to-end; start PBKDF2/PMK/PTK/MIC implementation; **Design Report due around here — target the baseline (Option A) as what's demoable at this checkpoint.**
- **Month 3:** PCFG + OMEN baselines implemented and validated against published numbers on public leak data; corpus construction begins.
- **Month 4:** ranker (fine-tuned small LM / hybrid) implemented; integration into guess loop; first cost-aware experiments.
- **Month 5:** guessability-estimator defense built and measured; ablations run; **fallback checkpoint — if the ranker underdelivers, this is where you retreat to Option A + PMF/deauth-detector defense and still submit a strong, complete Final Report.**
- **Month 6:** Final Report + demo polish; if results are strong, begin drafting a short paper for the venue strategy above.

---

## 19. Risk Analysis + Fallbacks

| Risk | Fallback |
|---|---|
| Own PBKDF2/EAPOL implementation has subtle bugs, crack loop never actually recovers a real password | Validate every stage against aircrack-ng's output on the *same* captured handshake before trusting your own numbers; budget Month 2 fully for this, don't rush it |
| Fine-tuned ranker doesn't beat PCFG/OMEN | That's a valid, reportable negative result if the ablations are honest — pivot framing to "under what conditions does a learned ranker help vs not," still a contribution |
| Corpus too small to be convincing | Be explicit about scale limitations in the report; supplement with the router-default-algorithm analysis (Lorente et al.-style), which doesn't require a large human-collected set |
| Guessability estimator is inaccurate | Fall back to the PMF/802.11w + deauth-detector defense (Section 11, secondary) — still earns the +10% |
| Research pipeline slips entirely | **The course grade never depends on the research succeeding** — the baseline (Option A: your own attack tool + PCFG/OMEN ranking + PMF defense) is fully built by Month 3–4 regardless, and is sufficient alone for full sessional marks + bonus |
| Time pressure from other courses (CSE401/CSE405/CSE453/CSE463 per your term load) | The roadmap above front-loads the *required* pipeline (Months 1–3) before the *research* layer (Months 4–6), so a compressed timeline still yields a passing, defensible baseline project |

---

## 20. Ethics and Responsible Research

- All capture, cracking, and defense testing happens against **your own AP(s)**, set up specifically for this project, with test passphrases you or consenting participants chose knowing they'd be used this way.
- No scanning, capturing, or attempting to crack any network you do not own or have explicit written authorization for.
- The corpus (Section 13) must be built from lab-only, disclosed test passphrases — never real production credentials, never real neighbors' networks.
- State this boundary explicitly and prominently in both the Design and Final reports — graders will expect it given the topic, and it's also just correct practice.

---

## 21. Final Recommendation

1. **Yes**, a research-shaped Project 20 is realistic — but only as a measurement/defense contribution around WPA2's real verification cost, not as an "LLM cracks Wi-Fi" story.
2. **Exact project:** own WPA2 handshake-capture-and-crack pipeline + cost-aware candidate-ranking evaluation (PCFG/OMEN baselines vs a small fine-tuned ranker, optionally SSID-conditioned) + guessability-estimator defense.
3. **Research question:** does guess-ranking quality translate into meaningfully different wall-clock cracking time once verification cost is realistically expensive (WPA2 PBKDF2), and does this differ between human-chosen and router-default Wi-Fi passphrases?
4. **Genuinely novel part:** evaluating generative password-guessing models against a realistic, expensive verification oracle instead of the field's usual cheap-hash assumption, on a Wi-Fi-specific (not web-leak) passphrase population.
5. **Use AI/ML?** Yes, but small and domain-fit (PCFG/OMEN/fine-tuned char-level or small transformer ranker) — explicitly **not** a general-purpose LLM prompted zero-shot; that's an empirically debunked approach (cite arXiv:2510.17884) and would weaken, not strengthen, the report.
6. **Core attack:** self-implemented 802.11 capture, deauth/PMKID acquisition, EAPOL parsing, PBKDF2→PMK→PTK→MIC verification loop.
7. **Defense:** guessability estimator at router-setup time (primary), 802.11w/PMF + deauth-burst check (fallback/secondary, cheap to also include).
8. **Convincing experiments:** the ablation isolating "cheap-hash cost model" vs "real PBKDF2 cost model" is the single most important chart in the paper — it's the direct visual argument for why this differs from prior generative-guessing evaluations.
9. **Venue to target first:** a regional/university security workshop or symposium; treat WOOT as an aspirational stretch goal after a solid workshop-tier draft exists; do not target USENIX Sec/CCS/S&P/NDSS as a first submission.
10. **Fallback if research fails:** Option A (baseline attack tool + PCFG/OMEN ranking + PMF defense) is fully sufficient for full sessional marks and the +10% bonus on its own, and is front-loaded early enough in the roadmap that it's never at risk.

---

## 22. Concrete First 2-Week Action Plan

1. **Days 1–2:** confirm hardware — a monitor-mode-capable Wi-Fi adapter (check chipset compatibility before buying/borrowing anything), set up an isolated test AP you fully control, get written/self-documented confirmation this is your own lab equipment.
2. **Days 2–4:** get raw 802.11 frame capture working (scapy or raw sockets) — passively capture beacons/probes from your own AP, parse BSSID/SSID/channel.
3. **Days 4–7:** implement deauth frame crafting; verify (on your own AP/client) that you can force a re-association and capture the resulting 4-way EAPOL exchange; separately implement PMKID extraction from the first EAPOL frame's RSN IE as a second capture path.
4. **Days 7–10:** implement the crypto verification chain (PBKDF2-HMAC-SHA1 → PMK → PTK via PRF → MIC) against a **known** password/handshake pair; cross-check against aircrack-ng on the identical .cap file until your numbers match exactly.
5. **Days 10–12:** wire the verification chain into a simple guess loop over a small wordlist; get an end-to-end "captured handshake → recovered password" demo working, even before any ranking model exists — this is your safety-net milestone.
6. **Days 12–14:** write up the Design Report skeleton (topology diagram, timing diagram, packet/frame details) using what you've built so far, and start reading the PCFG (Weir et al.) and OMEN (Dürmuth et al.) papers closely enough to implement them next.

A deeper literature synthesis (systematically pulling every paper cited above plus additional recent arXiv preprints, cross-checking claims, and drafting a formal related-work section) is the kind of broad, many-source task the Research feature is built for, if you want that level of depth for the Design/Final report's related-work section specifically.
