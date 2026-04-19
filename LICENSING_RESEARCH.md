# Repo Forensics Licensing Research & Drafts

**Context**: Tank (tankpkg/tank) founder asked about integration. Discussion surfaced that PolyForm NC creates ambiguity around "might commercialize someday" projects, blocking adoption from individual devs who fear future liability. This doc captures research and draft language to fix it without switching licenses.

**Date**: 2026-04-16
**Status**: Decision pending. Keep PolyForm NC. Add clarifying layer.

---

## TL;DR

1. The friction is real. PolyForm itself is releasing v2.0.0 to address it.
2. Successful PolyForm NC projects (EPPlus, GitNexus, Komorebi) all solve it with FAQs + dual license + honor-system enforcement.
3. Nobody publishes an explicit no-retroactive-charge commitment. Doing so is a positioning win.
4. No license change needed. Add FAQ + Courtesy Grant + Commercial Pricing page.

---

## Real-World Precedents

### EPPlus — the gold standard dual-license model
- **License**: PolyForm Noncommercial 1.0.0 + Commercial tier
- **Product**: .NET Excel library, $M+ annual revenue
- **Pattern**: PolyForm NC for community, paid commercial license for any use inside a commercial company
- **Key position**: "All usage within a commercial company requires a commercial license"
- **Validation**: They do NOT verify non-commercial claims themselves, burden on user
- **Links**:
  - [EPPlus LGPL to PolyForm migration rationale](https://www.epplussoftware.com/en/Home/LgplToPolyform)
  - [EPPlus License FAQ](https://www.epplussoftware.com/LicenseOverview/LicenseFAQ)
  - [EPPlus GitHub](https://github.com/EPPlusSoftware/EPPlus)

### GitNexus — 17K stars despite PolyForm NC
- **License**: PolyForm NC + enterprise commercial tier
- **Product**: Code intelligence for AI editors
- **Lesson**: Adoption happens, but enterprise friction is real and acknowledged
- **Links**:
  - [GitNexus background](https://byteiota.com/gitnexus-zero-server-code-intelligence-for-ai-editors/)

### Komorebi — custom stricter variant
- **License**: PolyForm Strict base + NC changes provisions, with nonprofit/org exemption removed
- **Product**: Windows tiling window manager
- **Pattern**: Individual personal use only, sponsorship model instead of per-seat licensing
- **Lesson**: Even stricter license builds strong community when the product is loved and stance is clear
- **Links**:
  - [Komorebi license repo](https://github.com/LGUG2Z/komorebi-license)

### PolyForm NC 2.0.0-pre.1 — license itself evolving
- **Status**: Released November 2025
- **Changes**: Condensed to under 550 words, 30-day cure period for violations, clearer "Personal Uses" definition
- **Why this matters**: Validates that the ambiguity is a real adoption problem the PolyForm authors are actively fixing
- **Links**:
  - [Kyle Mitchell announcement](https://writing.kemitchell.com/2025/11/04/PolyForm-Noncommercial-2.0.0-pre.1)
  - [PolyForm Project licenses index](https://polyformproject.org/licenses/)
  - [PolyForm NC 1.0.0 text](https://polyformproject.org/licenses/noncommercial/1.0.0/)

### Comparison projects (different models we considered)
- **Sidekiq** — LGPL + Pro/Enterprise paid tiers. [sidekiq.org](https://sidekiq.org/)
- **JetBrains** — proprietary + free for students/OSS. [jetbrains.com/store](https://www.jetbrains.com/store/)
- **MySQL** — GPL + Commercial dual license. Oracle extracts hundreds of millions annually.
- **Highcharts** — CC BY-NC + Commercial. Functional but legally awkward for software.

---

## What the Research Revealed

### The ambiguity problem is universal
Every successful PolyForm NC project has had the same adoption conversation. "Can I use this on a project that might go commercial?" The license text doesn't answer cleanly. The projects that win are the ones that answer it in their README.

### The "retroactive charge" fear is solvable but unaddressed
No PolyForm NC project explicitly publishes a no-retroactive-charge commitment. This is a positioning gap Repo Forensics can fill. Makes us more trustworthy than EPPlus on this dimension.

### The honor system is standard
Nobody actually audits non-commercial claims. EPPlus explicitly refuses to. Enforcement is cease-and-desist, not litigation. The license works because most people self-comply when the rules are clear.

### Dual-license is the dominant pattern
PolyForm NC as the base, paid commercial tier layered on top, published pricing OR clear sales contact. EPPlus hides behind login, which we can beat on transparency.

---

## Draft Additions (for review, not final)

### Draft 1: Short README banner (top of README, 1-2 lines)

> Repo Forensics is free for individuals and non-commercial use under PolyForm Noncommercial 1.0.0. Commercial use requires a license. Your past non-commercial use is never retroactively charged.

### Draft 2: Courtesy Grant section (new file or README section)

> **Author's Courtesy Grant**
>
> In addition to PolyForm Noncommercial 1.0.0, the author extends the following clarifications to individual developers:
>
> 1. **Personal projects that may commercialize later are free to scan** while they remain non-commercial. A commercial license is only required from the point commercial use begins, not retroactively.
>
> 2. **Past non-commercial use is never retroactively charged.** If you used Repo Forensics on a personal project before it commercialized, you owe nothing for that past usage. Commercial licensing applies going forward only.
>
> 3. **Tool use is not embedding.** Running Repo Forensics to audit your own code is free for personal/non-commercial purposes regardless of the code's future. Embedding Repo Forensics into a commercial product you distribute is different and requires a commercial license.
>
> 4. **Scope clarification.** Scanning code you personally own = free (non-commercial). Scanning code owned by your employer = commercial use (employer needs license). Scanning clients' code for pay = commercial use.

### Draft 3: FAQ entries (README section, 6-8 Q&As)

**Q: Can I scan my personal side project that might become a business later?**
A: Yes. Scanning is personal use while the project is non-commercial. If it commercializes, you'd need a commercial license for scans going forward, but never retroactively for past scans.

**Q: I'm an employee scanning my employer's code. Is that free?**
A: No. That's commercial use. Your employer needs a commercial license. Direct them to [pricing link].

**Q: I'm a security consultant scanning a client's repo.**
A: Commercial use. Your client needs a license, or you can purchase a consultant-tier license that covers your engagements.

**Q: I want to modify Repo Forensics for my personal workflow.**
A: Allowed for personal use. You cannot redistribute modified versions without a commercial license.

**Q: Can I contribute a PR?**
A: Yes, encouraged. Contributions are under the same license.

**Q: What if I'm a bootstrapped founder and can't afford commercial pricing yet?**
A: Contact the author. We offer founder-friendly pricing for pre-revenue startups.

**Q: How do you enforce the license?**
A: Honor system plus cease-and-desist for clear violations. We don't audit non-commercial claims. We trust individuals to self-determine. Most people do the right thing when the rules are clear.

**Q: What happens if the license changes in the future?**
A: Your rights under the version you adopted are preserved. Future versions do not retroactively apply.

### Draft 4: Pricing tier sketch (pricing page on a site or in README)

| Tier | Price | Use case |
|---|---|---|
| Individual Non-Commercial | Free | Personal projects, hobby, learning |
| Individual Commercial | $99/yr | Freelancer, solo consultant on paid client work |
| Startup (under $1M revenue) | $499/yr | Small team, pre-scale commercial use |
| Team / Company | $2,500/yr | Up to 25 developers |
| Enterprise | Contact | 25+ devs, compliance needs, custom terms |
| OEM / Embedding | Custom | Redistribution, SDK, platform integration |

(Numbers are placeholders for Alex's review.)

---

## Action Checklist

- [ ] Decide: keep PolyForm NC 1.0.0, or wait for 2.0.0 final release
- [ ] Review and finalize Courtesy Grant text
- [ ] Review and finalize FAQ entries
- [ ] Decide pricing tiers
- [ ] Add short banner to top of README
- [ ] Add Courtesy Grant section or separate file
- [ ] Add FAQ section
- [ ] Decide: pricing on README, separate page, or contact-based
- [ ] Optional: draft blog post announcing the clarifications (adoption win)
- [ ] Optional: monitor PolyForm NC 2.0.0 release, plan upgrade path

---

## Strategic Framing

This isn't a license change. It's a CLARITY LAYER on top of PolyForm NC that:

1. Preserves all commercial protection
2. Removes adoption friction for individuals
3. Eliminates retroactive-charge fear
4. Positions Repo Forensics as the most dev-friendly PolyForm NC project in the ecosystem

**The competitive angle**: EPPlus, GitNexus, and Komorebi all leave this psychological gap open. Closing it explicitly makes Repo Forensics stand out as "the scanner that respects devs."

---

## Sources

- PolyForm Project: https://polyformproject.org/
- PolyForm NC 1.0.0: https://polyformproject.org/licenses/noncommercial/1.0.0/
- PolyForm NC 2.0.0-pre.1: https://writing.kemitchell.com/2025/11/04/PolyForm-Noncommercial-2.0.0-pre.1
- EPPlus license FAQ: https://www.epplussoftware.com/LicenseOverview/LicenseFAQ
- EPPlus migration rationale: https://www.epplussoftware.com/en/Home/LgplToPolyform
- Komorebi license: https://github.com/LGUG2Z/komorebi-license
- GitNexus discussion: https://byteiota.com/gitnexus-zero-server-code-intelligence-for-ai-editors/
- Lobsters discussion on PolyForm: https://lobste.rs/s/5ngjnk/what_are_polyform_licenses
- PolyForm issue with commercial ambiguity (reference case): https://github.com/KavrakiLab/vamp/issues/13
