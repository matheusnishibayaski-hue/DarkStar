FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/exploitdb:/opt/john/run:${PATH}"
ENV SEC_LISTS="/usr/share/seclists"

RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf "deb http://deb.debian.org/debian bookworm main\n\
deb http://deb.debian.org/debian-security bookworm-security main\n" > /etc/apt/sources.list

# ── Pacotes APT ──────────────────────────────────────────────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates netbase curl wget git unzip tar jq \
    python3 python3-pip python3-venv ruby ruby-dev build-essential cmake \
    perl libnet-ssleay-perl libjson-perl \
    nmap masscan zmap arp-scan nbtscan netdiscover \
    fierce dnsenum dnsutils whois traceroute iputils-ping \
    hping3 ngrep tcpdump tshark \
    gobuster wfuzz dirb sqlmap whatweb siege \
    sslscan openssl snmp onesixtyone \
    hydra john medusa patator ncrack hashcat cewl crunch \
    smbclient samba-common-bin ldap-utils \
    hashid foremost binwalk file libimage-exiftool-perl steghide \
    binutils \
    wireless-tools iw rfkill usbutils pciutils kmod wpasupplicant \
    aircrack-ng reaver bully pixiewps mdk4 hcxdumptool hcxtools \
    proxychains4 netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# ── Binários Go/Rust (ProjectDiscovery + populares) ────────────────────────
RUN mkdir -p /tmp/dl && cd /tmp/dl \
    && curl -fsSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
       | tar xz && install -m755 ffuf /usr/local/bin/ffuf \
    && curl -fsSL https://github.com/epi052/feroxbuster/releases/download/v2.11.0/x86_64-linux-feroxbuster.tar.gz \
       | tar xz && install -m755 feroxbuster /usr/local/bin/feroxbuster \
    && curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o nuclei.zip \
    && unzip -q nuclei.zip nuclei && install -m755 nuclei /usr/local/bin/nuclei && rm nuclei.zip \
    && curl -fsSL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip -o subfinder.zip \
    && unzip -q subfinder.zip subfinder && install -m755 subfinder /usr/local/bin/subfinder && rm subfinder.zip \
    && curl -fsSL https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip -o httpx.zip \
    && unzip -q httpx.zip httpx && install -m755 httpx /usr/local/bin/httpx && rm httpx.zip \
    && curl -fsSL https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_amd64.zip -o naabu.zip \
    && unzip -q naabu.zip naabu && install -m755 naabu /usr/local/bin/naabu && rm naabu.zip \
    && curl -fsSL https://github.com/owasp-amass/amass/releases/download/v5.1.1/amass_linux_amd64.tar.gz \
       | tar xz && install -m755 amass /usr/local/bin/amass \
    && curl -fsSL https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip -o katana.zip \
    && unzip -q katana.zip katana && install -m755 katana /usr/local/bin/katana && rm katana.zip \
    && curl -fsSL https://github.com/projectdiscovery/dnsx/releases/download/v1.2.2/dnsx_1.2.2_linux_amd64.zip -o dnsx.zip \
    && unzip -q dnsx.zip dnsx && install -m755 dnsx /usr/local/bin/dnsx && rm dnsx.zip \
    && curl -fsSL https://github.com/projectdiscovery/tlsx/releases/download/v1.1.9/tlsx_1.1.9_linux_amd64.zip -o tlsx.zip \
    && unzip -q tlsx.zip tlsx && install -m755 tlsx /usr/local/bin/tlsx && rm tlsx.zip \
    && curl -fsSL https://github.com/projectdiscovery/uncover/releases/download/v1.0.9/uncover_1.0.9_linux_amd64.zip -o uncover.zip \
    && unzip -q uncover.zip uncover && install -m755 uncover /usr/local/bin/uncover && rm uncover.zip \
    && curl -fsSL https://github.com/projectdiscovery/shuffledns/releases/download/v1.1.0/shuffledns_1.1.0_linux_amd64.zip -o shuffledns.zip \
    && unzip -q shuffledns.zip shuffledns && install -m755 shuffledns /usr/local/bin/shuffledns && rm shuffledns.zip \
    && curl -fsSL https://github.com/hahwul/dalfox/releases/download/v3.1.0/dalfox-v3.1.0-linux-x86_64.tar.gz \
       | tar xz && install -m755 dalfox /usr/local/bin/dalfox \
    && curl -fsSL https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb -o rustscan.deb \
    && apt-get update && apt-get install -y ./rustscan.deb && rm rustscan.deb \
    && rm -rf /tmp/dl /var/lib/apt/lists/*

# ── Binários Go (OSINT, AD, proxy, cloud) ────────────────────────────────────
RUN mkdir -p /tmp/dl && cd /tmp/dl \
    && curl -fsSL https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz \
       | tar xz && install -m755 gau /usr/local/bin/gau \
    && curl -fsSL https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz \
       | tar xz && install -m755 waybackurls /usr/local/bin/waybackurls \
    && curl -fsSL https://github.com/tomnomnom/anew/releases/download/v0.1.1/anew-linux-amd64-0.1.1.tgz \
       | tar xz && install -m755 anew /usr/local/bin/anew \
    && curl -fsSL https://github.com/tomnomnom/qsreplace/releases/download/v0.0.1/qsreplace-linux-amd64-0.0.1.tgz \
       | tar xz && install -m755 qsreplace /usr/local/bin/qsreplace \
    && curl -fsSL https://github.com/hakluke/hakrawler/releases/download/2.1.0/hakrawler-linux-amd64 \
       -o hakrawler && install -m755 hakrawler /usr/local/bin/hakrawler \
    && curl -fsSL https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_linux_x86_64.zip -o gospider.zip \
    && unzip -q gospider.zip gospider && install -m755 gospider /usr/local/bin/gospider && rm gospider.zip \
    && curl -fsSL https://github.com/blechschmidt/massdns/releases/download/v1.0.0/massdns_Linux_x86_64.tar.gz \
       | tar xz && install -m755 bin/massdns /usr/local/bin/massdns \
    && curl -fsSL https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 \
       -o kerbrute && install -m755 kerbrute /usr/local/bin/kerbrute \
    && curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz \
       | gunzip > chisel && install -m755 chisel /usr/local/bin/chisel \
    && curl -fsSL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz \
       | tar xz && install -m755 proxy /usr/local/bin/ligolo-ng \
    && curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_Linux-64bit.tar.gz \
       | tar xz && install -m755 trivy /usr/local/bin/trivy \
    && rm -rf /tmp/dl

# ── Ferramentas via Git ──────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && git clone --depth 1 https://github.com/portcullislabs/enum4linux.git /opt/enum4linux \
    && ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux \
    && git clone --depth 1 https://github.com/darkoperator/dnsrecon.git /opt/dnsrecon \
    && ln -sf /opt/dnsrecon/dnsrecon.py /usr/local/bin/dnsrecon \
    && git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder \
    && printf '#!/bin/sh\nexec python3 /opt/Responder/Responder.py "$@"\n' > /usr/local/bin/responder \
    && chmod +x /usr/local/bin/responder \
    && git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch \
    && printf '#!/bin/sh\nexec python3 /opt/dirsearch/dirsearch.py "$@"\n' > /usr/local/bin/dirsearch \
    && chmod +x /usr/local/bin/dirsearch \
    && git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/XSStrike \
    && printf '#!/bin/sh\ncd /opt/XSStrike && exec python3 xsstrike.py "$@"\n' > /usr/local/bin/xsstrike \
    && chmod +x /usr/local/bin/xsstrike \
    && git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && printf '#!/bin/sh\ncd /opt/jwt_tool && exec python3 jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool \
    && git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists \
    && git clone --depth 1 https://github.com/kimocoder/wifite2.git /opt/wifite2 \
    && printf '#!/bin/sh\nexec python3 /opt/wifite2/wifite.py "$@"\n' > /usr/local/bin/wifite \
    && chmod +x /usr/local/bin/wifite

# ── Python (pip) e Ruby (gem) ────────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages \
    impacket wafw00f commix netexec theHarvester sublist3r enum4linux-ng \
    arjun certipy-ad ldapdomaindump bloodyAD smbmap evil-winrm droopescan \
    dnsgen crowbar volatility3 scoutsuite \
    && gem install wpscan --no-document \
    && nuclei -update-templates -silent 2>/dev/null || true

COPY wifi-entrypoint.sh wifi-status.sh /tmp/wifi-scripts/
RUN sed -i 's/\r$//' /tmp/wifi-scripts/* \
    && install -m755 /tmp/wifi-scripts/wifi-entrypoint.sh /usr/local/bin/wifi-entrypoint.sh \
    && install -m755 /tmp/wifi-scripts/wifi-status.sh /usr/local/bin/wifi-status \
    && rm -rf /tmp/wifi-scripts

WORKDIR /tools
ENTRYPOINT ["/usr/local/bin/wifi-entrypoint.sh"]
