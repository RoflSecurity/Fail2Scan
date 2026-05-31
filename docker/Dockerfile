FROM node:lts-bookworm
SHELL ["/bin/bash", "-c"]

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y nmap dnsutils whois
RUN npm install -g @roflsec/fail2scan

CMD [ "fail2scan-daemon", "--log", "/var/log/fail2ban.log", "--out", "/var/log/fail2scan", "--concurrency", "2", "--nmap-args", "-sS -Pn -p- -T4 -sV", "--quiet" ]
