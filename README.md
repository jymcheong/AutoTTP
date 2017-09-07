# AutoTTP
Automated Tactics Techniques &amp; Procedures. In short, re-running complex sequence for regression tests, product evaluations & so on can be tedious if done manually. I toyed with the idea of making it easier to script [Empire](https://github.com/EmpireProject/Empire) (or any framework like Metasploit, Cobalt & so on that provides APIs) using IDE like [Visual Studio Code](https://code.visualstudio.com) (or equivalent). This is still very much work in progress. 

## What is TTP?
![](screenshots/ttp.png)

In our case, the tactics are organized as per my [Attack Life Cycle model](https://jym.sg). One can use other models like Lockheed Martin's Kill-Chain(tm), Mandiant Attack Life Cycle & Mitre's ATT&CK (for post-exploitation). Whichever model it my be, *"Tactics" essentially help us group techniques together*:

![](screenshots/ALCmatrix.png)

Each "Tactics" row is associated to a "Stage". If you look into the source tree, the folder structure reflects this matrix. The matrix in this case also reflects the respective controls for each offensive tactic.

## How does Procedure look like?

![](screenshots/procedureVStechniques.png)