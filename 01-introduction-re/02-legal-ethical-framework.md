🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 1.2 — Legal and ethical framework

> **Chapter 1 — Introduction to Reverse Engineering**  
> 📦 No technical prerequisites — reading section.

---

## Why talk about law in a technical training?

Reverse engineering is a technical activity that directly touches on legal questions. Disassembling a piece of software means accessing its internal logic in a way the publisher generally did not foresee — and sometimes did not want. Depending on the context, the jurisdiction, and the software's terms of use, this activity may be perfectly legal, tolerated in a gray area, or constitute an offense.

Ignoring this legal framework does not protect you. A security professional who publishes a vulnerability analysis, a researcher who gives a conference talk, a developer who reverses a third-party library — all may find themselves facing legal questions if they have not taken a minimum of precautions upstream.

This section is not meant to replace legal advice. It aims to give you the essential landmarks to understand the legal landscape of RE, identify risky situations, and know when it is prudent to consult a lawyer. Legislation evolves and its interpretation varies across jurisdictions — what follows is a general overview, not legal advice.

> ⚠️ **This section describes the legal framework for informational and educational purposes only. It does not constitute legal advice. If in doubt about the legality of an RE activity in your context, consult a lawyer specialized in intellectual property or digital law.**

---

## The three legal pillars to know

Three families of texts govern RE in most Western jurisdictions: copyright protection of software, anti-circumvention laws for technical protection measures, and laws on unauthorized access to computer systems. Each operates at a different level and may — or may not — apply depending on what you do and why you do it.

---

## Copyright applied to software

### The principle

In almost every jurisdiction, software is protected by copyright from the moment of its creation. This protection covers the **source code** as a literary work, but also, in many countries, the **elements of the program** that express creative choices made by the author — which potentially includes structure, organization, and certain aspects of the object code.

Concretely, this means that copying, modifying, or distributing software (including in binary form) without the rights holder's authorization in principle constitutes a copyright infringement.

### Where does RE fit in?

Reverse engineering poses a delicate question for copyright: disassembling a binary produces an intermediate representation (assembly code, pseudo-code) which is technically a "reproduction" of the protected work, even if this representation is very far from the original source code.

The legal answer varies by country, but the general trend is to recognize **specific exceptions** for RE when it pursues certain legitimate objectives. We will come back to these in the section devoted to each piece of legislation.

### Software licenses

Even before asking about the law, you must look at the **license** of the software you wish to analyze. The license is a contract between the publisher and the user which defines the rights granted and the restrictions imposed.

**Open source software** — Open source licenses (MIT, GPL, BSD, Apache, etc.) generally grant the right to study the program's workings, including by examining the source code. RE of an open source binary is therefore rarely legally problematic: you have access to the source code, and the license explicitly authorizes you to study it. In practice, RE of an open source binary is primarily a learning exercise (comparing the binary to its source is an excellent way to progress).

**Proprietary software** — Proprietary licenses (EULA — *End User License Agreement*) frequently contain clauses that explicitly prohibit reverse engineering, disassembly, and decompilation. The legal weight of these clauses varies across jurisdictions:

- In **Europe**, a contractual clause cannot prohibit decompilation for interoperability purposes if the conditions set by the directive are met (see below). The clause is simply unenforceable on that point.  
- In the **United States**, the situation is more complex. Courts have sometimes given precedence to the contract (the EULA) over legal exceptions, and sometimes the opposite. The specific context of each case weighs heavily in the decision.

> 💡 **Practical rule** — Always read the license before reversing proprietary software. If it explicitly prohibits RE and you are not in a clearly established statutory exception case, you are taking a legal risk.

---

## The United States: DMCA and CFAA

### The DMCA — Digital Millennium Copyright Act (1998)

The **DMCA** is a U.S. federal law which, among other provisions, prohibits the **circumvention of technical protection measures** (TPMs) put in place by a rights holder to control access to a protected work.

In other words: if a piece of software is protected by an anti-copy mechanism, a license verification system, encryption, or any other technical measure designed to restrict access, the mere act of circumventing that measure can constitute a DMCA violation — independently of what you do with the software afterwards.

The DMCA also prohibits the **manufacture and distribution of tools** whose primary purpose is to enable the circumvention of such measures. This provision has historically stirred the most controversy in the computer security community.

**Notable exceptions for RE:**

The DMCA provides a specific exception for reverse engineering at 17 U.S.C. § 1201(f). This exception authorizes the circumvention of a technical protection measure **for interoperability purposes** between computer programs, under certain strict conditions:

- The person must have lawfully obtained a copy of the program.  
- RE must be necessary to identify and analyze the elements of the program required for interoperability.  
- The information obtained must not be used for other purposes or made available to third parties in a prejudicial way.

Beyond this codified exception, the U.S. **Copyright Office** periodically (every three years) grants **temporary exemptions** to the DMCA via a rulemaking process. Some of these exemptions concern computer security research directly. Since 2015, exemptions have been progressively broadened to cover *good faith security research*, provided conditions on vulnerability notification and the absence of violation of other laws are respected.

> ⚠️ **DMCA exemptions are limited in time and scope.** They are reassessed every three years and their exact contours evolve. If you conduct security research on proprietary software in the United States, or research liable to be subject to U.S. law, verify the exemptions in force at the time of your research.

### The CFAA — Computer Fraud and Abuse Act (1986, amended)

The **CFAA** is the main U.S. federal law on cybercrime. Unlike the DMCA (which deals with intellectual property and protection measures), the CFAA deals with **unauthorized access** to computer systems.

The text penalizes anyone who "intentionally accesses a computer without authorization, or exceeds authorized access". Penalties range from fines to prison sentences, depending on the nature and severity of the offense.

**How does the CFAA concern RE?**

As a general rule, reverse engineering a binary that you have installed locally on your own machine does not fall under the CFAA — you are accessing your own computer. The CFAA becomes relevant when RE involves interacting with a remote system (server, API, cloud service) in a way not provided for by the operator, or when the analyzed binary was obtained by accessing a system without authorization.

The CFAA has been widely criticized for the **vague definition** of the phrase "exceeds authorized access". For years, some prosecutors interpreted this notion very broadly, to the point that a mere violation of a website's terms of service could be prosecuted as a federal crime.

An important Supreme Court ruling, **Van Buren v. United States (2021)**, significantly narrowed this interpretation. The Court ruled that the CFAA only applies to people who access information located in areas of a system to which they have no access at all — not to people who access authorized information but use it for unintended purposes. This decision clarified the landscape for security research, even though its concrete implications continue to be refined by case law.

> 💡 **Summary for RE under U.S. law** — The DMCA concerns the circumvention of protection measures (DRM, license verifications). The CFAA concerns unauthorized access to systems. Both may apply depending on the context, and exceptions for security research and interoperability exist but are framed by precise conditions.

---

## Europe: EUCD directive and software directive

### The EUCD — European Union Copyright Directive (2001/29/EC)

The **EUCD** (sometimes called the *InfoSoc Directive*) is the European equivalent of the DMCA regarding technical protection measures. It prohibits the circumvention of effective technical measures put in place to protect a work, as well as the manufacture and distribution of circumvention tools.

Like the DMCA, the EUCD provides for exceptions, but it **leaves member states to transpose them** into their national law. The level of protection and the exceptions therefore vary from one European country to another.

In **France**, the transposition of the EUCD is integrated into the *Code de la propriété intellectuelle* (articles L. 331-5 et seq.). The DADVSI law (2006) was the main vehicle for this transposition. Circumvention of technical protection measures is penalized, with limited exceptions (private copy, accessibility, computer security under certain conditions).

### The directive on the legal protection of computer programs (2009/24/EC)

This is the most important text for RE in Europe. This directive (which codified and replaced directive 91/250/EEC of 1991) establishes an **explicit right to decompilation** for interoperability purposes, under conditions.

Article 6 of the directive authorizes the reproduction of the code and the translation of its form (that is, decompilation) **without the rights holder's authorization** when the following three cumulative conditions are met:

1. **The act is performed by a licensee** (who has the right to use a copy of the program) or by a person authorized by the licensee.  
2. **The information necessary for interoperability is not readily and quickly accessible** through other means (public documentation, open APIs, etc.).  
3. **The act is limited to the parts of the program necessary for interoperability.**

Furthermore, the information obtained through this decompilation cannot be used for purposes other than interoperability, cannot be communicated to third parties (unless necessary for interoperability), and cannot be used to develop a substantially similar competing program.

A ruling by the Court of Justice of the European Union (CJEU) provided significant clarification in 2021 in the case **Top System SA v. Belgian State (C-13/20)**: decompilation may be authorized not only to ensure interoperability, but also to **correct errors** affecting the operation of the program, including security flaws. The Court broadened the interpretation of Article 5(1) of the directive, ruling that the licensee has the right to decompile the program to the extent necessary to correct those errors.

> 💡 **Summary for RE in Europe** — The European framework is overall more favorable to RE than the U.S. framework, notably thanks to the explicit right of decompilation for interoperability (and now for error correction). However, this framework imposes strict conditions and does not cover all RE objectives (pure offensive security research, for example, is not explicitly covered by the interoperability exception). Transposition varies by country — check your national law.

---

## Other jurisdictions

The legal landscape varies considerably by country. A few landmarks, without claiming to be exhaustive:

**United Kingdom** — The *Copyright, Designs and Patents Act 1988* (as amended) contained provisions similar to the European directives. Since Brexit, the United Kingdom has its own framework, which largely reproduces the exceptions for interoperability and security research, but can evolve independently of EU law.

**Japan** — Japanese copyright law has authorized RE for security research purposes since a 2018 revision, making it one of the most permissive jurisdictions for computer security research.

**China** — Software protection is ensured by a specific regulation on software copyright protection. Exceptions for RE are limited and case law is developing.

> ⚠️ This overview is necessarily incomplete. If you practice RE in a professional context or if your results are intended to be published, check the applicable law in your jurisdiction.

---

## The ethical framework: beyond the law

Complying with the law is a minimum, not a sufficient goal. Reverse engineering raises ethical questions that the law does not always settle.

### Responsible disclosure

If you discover a vulnerability in a piece of software during an RE analysis, the question of disclosure arises immediately. The standard practice in the security community is **responsible disclosure** (also called *coordinated disclosure*):

1. You contact the software publisher privately to report the vulnerability.  
2. You grant them a reasonable timeframe to develop and deploy a fix (90 days is a common standard, popularized by Google Project Zero).  
3. You publish the details of the vulnerability once the fix is available, or when the deadline expires if the publisher has not responded.

This practice is not always a legal obligation (although some sectoral regulations impose it), but it is a widely recognized ethical standard. Publishing a vulnerability without giving the publisher time to patch (immediate *full disclosure*) exposes users of the software to a risk of exploitation, while never disclosing it leaves the vulnerability open indefinitely.

### Respect for purpose

The ability to reverse a piece of software does not mean that every use of the information obtained is acceptable. A few basic principles:

- **Do not use RE to steal intellectual property.** Understanding how an algorithm works to ensure interoperability is different from copying that algorithm to develop a competing clone.  
- **Do not distribute pirated software.** Understanding how a license verification works for learning purposes (as in the practical cases of this training) is different from distributing a crack to the public.  
- **Do not exploit the vulnerabilities you discover.** Identifying a flaw in a piece of software as part of an authorized audit is legitimate. Exploiting it against third-party systems without authorization is a criminal offense, regardless of the jurisdiction.

### The special case of this training

In this training, all binaries analyzed are **compiled by you** from provided sources, or are binaries created specifically for educational purposes. You will not reverse any proprietary software, and no real malicious sample is distributed.

This framing eliminates almost all legal risks: you are analyzing your own programs, on your own machine, for learning purposes. It is the digital equivalent of taking apart your own watch to understand how it works.

The skills you develop here should then be applied in compliance with the legal and ethical framework of your jurisdiction and your professional context.

---

## Summary of key texts

| Text | Jurisdiction | Covers | Notable RE exception |  
|---|---|---|---|  
| DMCA (17 U.S.C. § 1201) | United States | Circumvention of technical measures | § 1201(f): interoperability; triennial exemptions for security research |  
| CFAA (18 U.S.C. § 1030) | United States | Unauthorized access to a system | No explicit RE exception; *Van Buren* (2021) narrowed the scope of the text |  
| EUCD (2001/29/EC) | European Union | Circumvention of technical measures | National transposition varies; possible exceptions for security and interoperability |  
| Directive 2009/24/EC art. 6 | European Union | Decompilation of software | Right of decompilation for interoperability (and error correction since *Top System*, 2021) |  
| DADVSI (2006) | France | EUCD transposition | Limited exceptions; see *Code de la propriété intellectuelle* art. L. 331-5 et seq. |

---

> 📖 **Takeaway** — RE is legal in many contexts, but it is not an absolute right. The legal framework depends on your jurisdiction, the software license, the objective pursued, and the possible presence of technical protection measures. In Europe, the right of decompilation for interoperability is explicitly protected. In the United States, the DMCA exceptions and CFAA case law offer space for security research, but with strict conditions. When in doubt, consult a lawyer before reversing proprietary software in a professional context.

---


⏭️ [Legitimate use cases: security auditing, CTF, advanced debugging, interoperability](/01-introduction-re/03-legitimate-use-cases.md)
