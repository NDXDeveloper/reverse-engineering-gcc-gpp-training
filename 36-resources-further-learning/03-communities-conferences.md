🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 36.3 — Communities and Conferences (REcon, DEF CON RE Village, PoC||GTFO, r/ReverseEngineering)

> 📁 `36-resources-further-learning/03-communities-conferences.md`

---

## Why community matters as much as technique

Reverse engineering is often perceived as a solitary activity — an analyst alone in front of a disassembler, armed with patience and coffee. In reality, the best reverse engineers in the world constantly rely on their community. They share techniques in write-ups, present their research at conferences, exchange tools and scripts on forums, and discuss concrete problems on specialized channels.

Joining these communities brings three concrete benefits. The first is **exposure to different approaches**: faced with the same binary, ten analysts will employ ten different strategies, and each one reveals something about the possibilities of tooling and methodology. The second is **passive monitoring**: by following discussions, you naturally absorb new techniques, new tools, and domain trends without structured effort. The third is the **professional network**: in a field as specialized as RE, career opportunities often circulate by word of mouth within the community before appearing on traditional job platforms.

---

## Conferences

### REcon — The conference dedicated to reverse engineering

**Location**: Montreal, Canada (Hilton DoubleTree)  
**Frequency**: Annual, in June  
**2026 edition**: June 19-21 (conference) + June 15-18 (training)  
**Website**: [recon.cx](https://recon.cx)  

REcon is *the* world's leading conference for reverse engineering. Held in Montreal since 2005, it brings together the most recognized experts in the field each year — vulnerability researchers, malware analysts, RE tool developers, and exploitation specialists. The conference uses a single-track format (one presentation room) ensuring all attendees see the same talks, fostering rich discussions between sessions.

The technical content is of very high caliber. Presentations cover RE across all platforms (Windows, Linux, macOS, embedded, mobile), advanced malware analysis, exploitation techniques, deobfuscation, and tool development. The 2026 edition notably offers 19 four-day training courses, including courses taught by Google's FLARE team on modern Windows malware analysis, software deobfuscation training by Tim Blazytko, RE of Rust binaries, and courses on RE automation with AI agents and the Model Context Protocol.

REcon is where the creators of Ghidra, IDA Pro, Binary Ninja, Frida, and many other tools we used throughout this training course come together. It is also where new techniques are often announced that will become domain standards a few months later.

> 💡 Videos from previous editions are available on REcon's YouTube channel. This is a first-rate free resource for accessing expert-level presentations.

**Cost**: Conference registration is paid (sliding scale based on registration date). Training courses are billed separately (approximately 5,500 to 6,000 CAD for four days). For students or limited budgets, the online videos are an excellent alternative.

---

### DEF CON — The global hacker gathering

**Location**: Las Vegas, United States (Las Vegas Convention Center)  
**Frequency**: Annual, in August  
**2026 edition**: DEF CON 34, August 6-9; DEF CON Singapore April 28-30  
**Website**: [defcon.org](https://defcon.org)  

DEF CON is the largest and most famous hacker convention in the world, held annually in Las Vegas since 1993. Unlike REcon which focuses on RE, DEF CON covers the entire spectrum of information security: pentesting, social engineering, hardware hacking, cryptography, forensics, AI, and of course reverse engineering.

One of DEF CON's most distinctive aspects is its **village** system — self-managed thematic spaces, each dedicated to a specific domain. For RE, several villages are relevant: the **Hardware Hacking Village** regularly features reverse engineering challenges on circuits and embedded firmware, the **IoT Village** allows practicing RE on real connected devices, and the **Packet Hacking Village** touches on network protocol analysis. DEF CON's main CTF, organized by teams like Nautilus Institute, always includes very high-level RE challenges.

DEF CON also offers **training courses** before the conference. The 2026 edition notably includes courses on RE automation with AI agents and Ghidra. In 2026, DEF CON extends beyond Las Vegas with editions in Singapore (April 28-30) and Bahrain (DEF CON Middle East, November 11-12).

**Cost**: DEF CON admission is relatively accessible compared to other security conferences (cash payment only, historically). Training courses are billed separately. However, travel and accommodation in Las Vegas represent a significant budget.

---

### SSTIC — The leading French-language conference

**Location**: Rennes, France (Couvent des Jacobins)  
**Frequency**: Annual, early June  
**2026 edition**: June 3-5  
**Website**: [sstic.org](https://www.sstic.org)  

The Symposium sur la Sécurité des Technologies de l'Information et des Communications (SSTIC) is the leading French-language conference on information security. Held in Rennes since 2003, it brings together approximately 800 participants from academia, industry, and government organizations (ANSSI, DGSE, French Ministry of Armed Forces).

SSTIC favors high-level technical and scientific contributions. Topics cover hardware security, system and software security (including reverse engineering and malware analysis), network security, cryptography, and analysis of offensive tools. Presentations are in French, and the complete proceedings are published freely online — constituting an archive of high-quality French-language technical articles.

Each year, SSTIC is accompanied by a **technical challenge** (published a few weeks before the conference) that systematically includes reverse engineering tasks. Solving the SSTIC challenge is an excellent goal for validating an intermediate-to-advanced skill level.

For a French speaker interested in RE and security, SSTIC is a must — both for its technical content and for the professional network it enables within the French cyber ecosystem.

**Cost**: Tickets are affordable but sell out extremely fast (within minutes of sales opening). Proceedings are freely accessible online.

---

### Other relevant conferences

**Black Hat** (Las Vegas, August / Europe, December) — The most established professional security conference, held just before DEF CON in Las Vegas. The content is of excellent quality but the orientation is more professional/commercial. The Briefings regularly include RE and malware analysis presentations. The Arsenal sessions allow discovering new tools.

**Hack.lu** (Luxembourg, October) — A European security conference with a good balance between accessibility and technical depth. RE content is regular and videos are published online.

**OffensiveCon** (Berlin, typically in May) — A highly technical conference focused on exploitation and advanced RE. The audience is predominantly composed of vulnerability researchers and offensive analysts. The presentation level is comparable to REcon.

**BlackHoodie** ([blackhoodie.re](https://blackhoodie.re)) — A nonprofit organization (501(c)(3)) founded in 2015 by Marion Marschalek (security engineer, former offensive researcher at Intel) offering free RE and malware analysis workshops for women. The workshops take place alongside conferences such as REcon, DEF CON, Troopers, DistrictCon, and Sec-T. The goal is to lower barriers to entry in a historically less diverse field. Several BlackHoodie participants have gone on to become trainers and speakers on the main conference circuit.

**LeHack** (Paris, June — [lehack.org](https://lehack.org)) — Formerly Nuit du Hack, LeHack is one of the oldest and largest hacking conferences in France. Held at the Cité des Sciences in Paris (2026 edition June 26-28), it combines technical talks, hands-on workshops, and an open-to-all CTF. Content covers pentesting, RE, hardware hacking, and offensive security. It is an event accessible to students and enthusiasts, with a good balance between advanced content and openness to beginners — a natural complement to SSTIC for the French-speaking audience.

**Barbhack** (Toulon, August) — A relaxed French conference with solid technical content, including RE.

**Hardwear.io** (Amsterdam / USA) — For those who wish to explore hardware and embedded RE beyond pure software.

---

## Community publications

### PoC||GTFO — The legendary zine

**Archives**: [pocorgtfo.hacke.rs](https://pocorgtfo.hacke.rs) and [github.com/angea/pocorgtfo](https://github.com/angea/pocorgtfo)  
**Print edition**: No Starch Press (3 volumes)  

PoC||GTFO (*Proof of Concept or Get The Fuck Out*) is a technical journal in the format of a religious tract, orchestrated by "Pastor Manul Laphroaig" (alias Travis Goodspeed) and a community of contributors including some of the most respected reverse engineers in the world: Ange Albertini (expert in file formats and polyglot files), Natalie Silvanovich (Google's Project Zero), Colin O'Flynn (side-channel attacks), Peter Ferrie (anti-malware expert), and many others.

The content is a unique mix of deeply technical articles — reverse engineering of amateur radios, microcontroller exploitation, ELF infection techniques, polyglot files that are simultaneously PDFs, ZIPs, and images — and philosophical essays on hacker culture, all with an ever-present deadpan humor. The PDF files of the issues are themselves proofs of concept: each issue is a polyglot file valid in multiple formats simultaneously.

PoC||GTFO is not a beginner's entry point. It is a read that rewards readers who already have a solid technical foundation — typically the level reached by the end of this training course. But it is also an incomparable source of inspiration about what a skilled engineer can accomplish with curiosity and free time. The three compiled volumes are published by No Starch Press as bible-format books (faux-leather cover, gilt edges, bookmark), true to the zine's aesthetic.

---

### tmp.out — The ELF/Linux zine

**Archives**: [tmpout.sh](https://tmpout.sh)

tmp.out is a research group and zine founded in 2021, entirely dedicated to the ELF format and Linux hacking. It is the publication most directly aligned with the focus of this training course: every article deals with ELF binaries, infection techniques, binary instrumentation, polymorphic code, or subtleties of the Linux loader. The contributions are deeply technical and constitute an advanced extension of our Chapters 2 (ELF format, sections, segments) and 19 (anti-reversing). tmp.out is read by both security researchers and the underground community — a rare bridge between the two worlds.

---

### Phrack Magazine

**Archives**: [phrack.org](http://phrack.org)

Phrack is the oldest hacker zine still in operation, published since 1985. Historically focused on exploitation and offensive security, Phrack has published some of the most influential articles in the field: code injection techniques in ELF, heap exploitation, anti-forensics techniques, and kernel vulnerability analyses. Issue 71, published in August 2024 at DEF CON 32 after three years of silence, confirmed the project's vitality with articles covering kernel exploitation, deoptimization evasion, and advanced format strings. The archives constitute a historical goldmine for understanding the evolution of RE and exploitation techniques.

---

## Online forums and discussion spaces

### r/ReverseEngineering

**URL**: [reddit.com/r/ReverseEngineering](https://reddit.com/r/ReverseEngineering)

The r/ReverseEngineering subreddit is the primary English-language RE content aggregator. Members share blog articles, CTF write-ups, tool announcements, academic papers, and technical discussions. Moderation maintains a high quality level: content is technical, beginner questions are directed to r/REGames, and spam is filtered.

It is the ideal place for passive monitoring of the field. By checking the subreddit a few times a week, you will have an up-to-date view of the publications, tools, and techniques circulating in the community. Discussions in the comments are often as instructive as the shared articles themselves.

---

### Tuts 4 You

**URL**: [forum.tuts4you.com](https://forum.tuts4you.com)

One of the oldest online communities dedicated to reverse engineering, active since the 2000s. Tuts 4 You specializes in unpacking, cracking, and reverse engineering of software protections. The forum offers tutorials, tools (often developed by the community), and technical discussions on bypassing packers, protection virtual machines, and obfuscators. It is also on Tuts 4 You that community events like the crackmes.one CTF are shared (see Section 36.1).

The community is known for its culture of knowledge sharing and its welcoming attitude toward motivated beginners, provided they demonstrate effort in their questions.

---

### Discord and specialized channels

Several active communities exist on Discord, although their ephemeral nature makes links less permanent than forums. Among the most relevant:

The **crackmes.one Discord** is directly linked to the challenge platform of the same name. It is a good place to ask for hints (without spoilers) on ongoing crackmes and to exchange with other practitioners.

**Tool-specific Discord servers** — Ghidra, Binary Ninja, Cutter/Radare2 — are valuable places to ask questions about advanced usage of these tools, report bugs, and discover plugins or scripts developed by the community.

**CTF servers** — many CTF teams have an open or semi-open Discord. Joining a team, even an informal one, is one of the best ways to progress quickly: you benefit from direct feedback from more experienced players on your approaches.

---

### Mastodon / Fediverse (infosec.exchange)

Since part of the security community migrated away from Twitter/X, the **infosec.exchange** instance on Mastodon has become a rallying point for many security researchers and reverse engineers. REcon, SSTIC, and many individual researchers post there regularly. It is a monitoring channel complementary to Reddit.

---

## Recommended integration path

Integrating into the RE community does not happen overnight, and you do not need to get involved everywhere. Here is a progressive approach:

**Step 1 — Observe**: Subscribe to r/ReverseEngineering and follow a few RE accounts on Mastodon or the social network of your choice. Read the write-ups shared there, even if you do not understand everything. Watch conference videos (REcon, SSTIC, DEF CON) on YouTube. The goal is to familiarize yourself with the vocabulary, tools, and approaches of the community.

**Step 2 — Participate online**: Publish your own CTF write-ups, even simple ones. Ask questions on forums and Discords after doing your research. Contribute to an open-source project related to RE (a Ghidra plugin, a YARA rule, an analysis script). The RE community highly values technical contributions, regardless of their size.

**Step 3 — Meet in person**: Attend a conference. For a French speaker, SSTIC is the most natural entry point. If budget allows, REcon and DEF CON offer an incomparable immersion. In-person meetings transform pseudonyms into faces and open doors that no online interaction can open.

**Step 4 — Contribute**: Submit a talk or a tool to a CFP (Call for Papers). SSTIC accepts submissions in French, which lowers the language barrier. Rump sessions (short 5-minute presentations) are an ideal format for a first conference speaking experience.

---

## Summary table

| Resource | Type | Language | Cost | RE Focus | Frequency |  
|---|---|---|---|---|---|  
| **REcon** | Conference | EN | Paid | Exclusive | Annual (June) |  
| **DEF CON** | Conference | EN | Paid | Partial (villages, CTF) | Annual (August) + regional events |  
| **SSTIC** | Conference | FR | Paid (free proceedings) | Strong | Annual (June) |  
| **Black Hat** | Conference | EN | Paid (expensive) | Partial | Bi-annual (USA + Europe) |  
| **LeHack** | Conference | FR | Paid | Partial | Annual (June) |  
| **BlackHoodie** | Workshop | EN | Free | Exclusive | Several per year |  
| **PoC\|\|GTFO** | Zine | EN | Free (PDF) | Strong | Irregular |  
| **tmp.out** | Zine | EN | Free | Exclusive (ELF/Linux) | Irregular |  
| **Phrack** | Zine | EN | Free | Strong | Irregular |  
| **r/ReverseEngineering** | Forum | EN | Free | Exclusive | Continuous |  
| **Tuts 4 You** | Forum | EN | Free | Exclusive | Continuous |  
| **infosec.exchange** | Social network | EN/FR | Free | Partial | Continuous |

---

**Next section: 36.4 — Certification Paths (GREM, OSED)**

⏭️ [Certification Paths: GREM (SANS), OSED (OffSec)](/36-resources-further-learning/04-certifications.md)
