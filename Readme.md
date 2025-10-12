

---

Fail2Scan

Fail2Scan is a Node.js daemon that watches your Fail2Ban logs for banned IP addresses and automatically scans them using system tools (nmap, dig, whois). All results are saved in a structured folder for easy review.


---

Features

Watches Fail2Ban logs in real time.

Detects new banned IPs automatically.

Runs nmap for full port scanning.

Runs dig for reverse DNS lookup.

Runs whois for IP ownership and ASN info.

Saves output in /var/log/fail2scan/<YYYY-MM-DD>/<IP>_<timestamp>/.

Pure Node.js, no external dependencies, works with Node 18+.

Compatible with PM2 or any process manager.



---

Installation

# Install globally
sudo npm install -g @roflsec/fail2scan


---

Usage

# Start daemon (default settings)
fail2scan-daemon

# Custom log file, output directory, concurrency, nmap arguments, quiet mode
fail2scan-daemon --log /var/log/fail2ban.log --out /var/log/fail2scan --concurrency 2 --nmap-args "-sS -Pn -p- -T4 -sV" --quiet

CLI Options

Option	Default	Description

--log	/var/log/fail2ban.log	Path to your Fail2Ban log file.
--out	/var/log/fail2scan	Output directory for scan results.
--concurrency	1	Number of scans to run in parallel.
--nmap-args	-sS -Pn -p- -T4 -sV	Arguments to pass to nmap.
--quiet	false	Suppress console output.
--help / -h		Show usage info.



---

Output Structure

Results are saved in this format:

/var/log/fail2scan/
└─ 2025-10-12/
   └─ 192.168.1.100_2025-10-12T14-30-00Z/
      ├─ nmap.txt      # raw nmap output
      ├─ dig.txt       # raw dig output
      ├─ whois.txt     # raw whois output
      └─ summary.json  # JSON summary of scan results

summary.json includes:

ip – scanned IP

timestamp – ISO timestamp of scan

commands – details of each scan (nmap, dig, whois)

open_ports – array of open ports detected by nmap



---

Requirements

Node.js 18+

System tools installed: nmap, dig, whois

Permissions to read Fail2Ban logs and write to the output directory


# Debian/Ubuntu example
sudo apt install nmap dnsutils whois


---

Running with PM2

# Start daemon with PM2
pm2 start $(which fail2scan-daemon) -- --log /var/log/fail2ban.log --out /var/log/fail2scan
pm2 save
pm2 status


---

License

MIT © RoflSec
