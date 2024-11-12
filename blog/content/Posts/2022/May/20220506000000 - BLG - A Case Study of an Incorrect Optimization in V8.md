---
ID: 20220506000000
tags:
  - Blogging
  - vuln_research/n-day
  - Sharing-session
Created: 2023-09-05 17:22:00
Last Modified: 2023-09-05 17:22:00
date: 2020/05/06
---
![[Pasted image 20241113024738.png]]
# Description

A presentation showing how it is possible for incorrect optimizations in the **JIT (Just-In-Time)** engine to lead to out of bound read and write.

![](https://youtu.be/Ihc9WbtruE8?si=TuBss8gsCvZmfOaj)

I was given the honor of presenting a small talk for NUS Security Wednesday. The main goal was to do a small case study on CVE-2021-30599, a bug reported by `@manfp` in Google Chrome V8 JavaScript Engine. The bug report was really well written and so unlike my previous analysis, I aimed to “reverse engineer” the author’s thought process during the exploit development. 

The reason is, the bug found was seemingly harmless but @manfp managed to transform that to a type-confusion bug, leading to Out Of Bounds access, and he chained that with a typer hardening bypass in Chrome V8 to eventually lead to RCE in the renderer’s process. In the quest to find out how that happen, I studied how he did that with the help of Turbolizer ( a visualization tool that shows the optimization process and dependencies within the JIT engine ).

You can download the pptx slides from [github](https://github.com/star-sg/Presentations/tree/main/NUS%20GreyHats%20SecWed%20Apr%202021)