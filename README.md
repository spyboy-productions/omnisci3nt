<h4 align="center">⭐️ If you find this GitHub repo useful, please consider giving it a star! ⭐️</h4>
<p align="center">
  <a href="https://github.com/spyboy-productions/omnisci3nt/stargazers">
    <img src="https://img.shields.io/github/stars/spyboy-productions/omnisci3nt?color=yellow&style=for-the-badge" alt="Stars">
  </a>
  <a href="https://github.com/spyboy-productions/omnisci3nt/network/members">
    <img src="https://img.shields.io/github/forks/spyboy-productions/omnisci3nt?color=orange&style=for-the-badge" alt="Forks">
  </a>
  <a href="https://github.com/spyboy-productions/omnisci3nt/issues">
    <img src="https://img.shields.io/github/issues/spyboy-productions/omnisci3nt?style=for-the-badge" alt="Issues">
  </a>
  <a href="https://github.com/spyboy-productions/omnisci3nt/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/spyboy-productions/omnisci3nt?style=for-the-badge" alt="License">
  </a>
</p>
<p align="center">
    <a href="https://spyboy.in/twitter">
        <img src="https://img.shields.io/badge/-TWITTER-black?logo=twitter&style=for-the-badge">
    </a>
    &nbsp;
    <a href="https://spyboy.in/">
        <img src="https://img.shields.io/badge/-spyboy.in-black?logo=google&style=for-the-badge">
    </a>
    &nbsp;
    <a href="https://spyboy.blog/">
        <img src="https://img.shields.io/badge/-spyboy.blog-black?logo=wordpress&style=for-the-badge">
    </a>
    &nbsp;
    <a href="https://spyboy.in/Discord">
        <img src="https://img.shields.io/badge/-Discord-black?logo=discord&style=for-the-badge">
    </a>
</p>

<p align="center">
    <img width="100%" src="https://github.com/spyboy-productions/omnisci3nt/blob/main/image/omnisci3nt1.png" />
</p>

---

## 🕵️‍♂️ Omnisci3nt: One Tool to Rule All Recon

Omnisci3nt is a powerful and comprehensive web reconnaissance toolkit tailored to cybersecurity professionals, ethical hackers, and digital investigators. It allows you to uncover hidden information about domains, analyze configurations, detect technologies, and explore archived content from the web.

Whether you're analyzing a target for vulnerabilities or simply exploring the technical details of a website, Omnisci3nt provides an all-in-one solution to automate and streamline your reconnaissance process.

---

### ☁️ Run It Instantly on Google Colab (No Installation Needed)

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/spyboy-productions/omnisci3nt/blob/main/omnisci3nt.ipynb)

> 💡 *For full functionality and better performance, a local installation is recommended.*

---

### ⚙️ Key Features

| Feature | Description |
|--------|-------------|
| IP Lookup | Retrieve geolocation and ISP data |
| WHOIS Lookup | Get domain registration information |
| HTTP Header Analysis | Analyze response headers |
| SSL Inspection | Fetch and inspect SSL certificate |
| DNS Enumeration | Gather DNS, Reverse, and Shared DNS records |
| Subdomain Discovery | Identify subdomains using various techniques |
| Port Scanning | Scan and detect open ports |
| Directory Brute-Force | Discover hidden files and directories |
| Web Crawling | Fetch links, robots.txt, and sitemap.xml |
| Tech Detection | Detect technologies used by the website |
| Wayback Machine | View archived pages over time |
| DMARC Analysis | Check domain email authentication (SPF, DKIM, DMARC) |
| Social Media Discovery | Extract social profiles and emails |
| Admin Panel Detection | Identify admin login portals |
| Reverse DNS Lookup | Get hostnames from IP addresses |
| Shared DNS Lookup | Discover other domains on the same DNS server |
| Full Recon Mode | Run all modules for deep analysis |

---

<h4 align="center">🖥️ OS Compatibility</h4>
<p align="center">
  <img src="https://img.shields.io/badge/Windows-05122A?style=for-the-badge&logo=windows">
  <img src="https://img.shields.io/badge/Linux-05122A?style=for-the-badge&logo=linux">
  <img src="https://img.shields.io/badge/Android-05122A?style=for-the-badge&logo=android">
  <img src="https://img.shields.io/badge/macOS-05122A?style=for-the-badge&logo=macos">
</p>

<h4 align="center">🧰 Requirements</h4>
<p align="center">
  <img src="https://img.shields.io/badge/Python-05122A?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/Git-05122A?style=for-the-badge&logo=git">
</p>

---

### 🧪 Installation

```bash
git clone https://github.com/spyboy-productions/omnisci3nt.git
cd omnisci3nt
pip3 install -r requirements.txt
python3 -m omnisci3nt.omnisci3nt -h
```
### ⭔ Example Usage :
```
python -m omnisci3nt.omnisci3nt -whois example.com
```

---

### 🚀 pipx Installation (Recommended)

Install via [`pipx`](https://github.com/pypa/pipx) for isolated, global access:

#### Step 1: Install `pipx`
```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

#### Step 2: Install Omnisci3nt
```bash
pipx install git+https://github.com/spyboy-productions/omnisci3nt.git
```

---

### 💡 Example Usage

```bash
omnisci3nt -whois example.com
```

---

### 🧭 All Command Options

| Command | Description |
|--------|-------------|
| `-ip <domain>` | IP geolocation info |
| `-headers <domain>` | Show HTTP headers |
| `-whois <domain>` | WHOIS lookup |
| `-ssl <domain>` | SSL certificate analysis |
| `-dns <domain>` | DNS enumeration |
| `-reversedns <domain>` | Reverse DNS lookup |
| `-shareddns <domain>` | Domains on the same DNS |
| `-subdomains <domain>` | Subdomain enumeration |
| `-dmarc <domain>` | DMARC record validation |
| `-crawl <domain>` | Crawl and fetch links |
| `-robots <domain>` | Fetch robots.txt and sitemap.xml |
| `-tech <domain>` | Detect technologies used |
| `-wayback <domain>` | Archive data from Wayback Machine |
| `-social <domain>` | Extract social media/email |
| `-dirscan <domain>` | Directory brute-force |
| `-portscan <domain>` | Port scanning |
| `-admin <domain>` | Admin panel finder |
| `-all <domain>` | Run all tools in one go |

### Optional command for pipx:

```
🔄 To upgrade from GitHub
pipx upgrade omnisci3nt

# If you originally installed using a local directory (pipx install .), then use:
pipx install . --force

❌ To uninstall
pipx uninstall omnisci3nt

# Bonus: Check where it's installed
pipx list
```

---

## 🤝 Contribute

Pull requests and issues are welcome! Found a bug? Have an idea? Let’s collaborate to improve Omnisci3nt.

---

## 🧠 To-Do List

- [ ] Integration with [urlscan.io](https://urlscan.io)
- [ ] Email spoofability check via MX records
- [ ] Reverse IP lookup (domain neighbors)
- [ ] Banner grabbing
- [ ] CVE-based vulnerability check (top techs)

---

## 💬 Community & Support

Need help or want to suggest a feature? Join our Discord server and connect with the community.

[![Join Discord](https://discord.com/api/guilds/726495265330298973/embed.png)](https://discord.gg/ZChEmMwE8d)

---

### 📸 Snapshots

<p align="center">
  <img src="https://github.com/spyboy-productions/omnisci3nt/blob/main/image/Screenshot_2023-08-16_at_3.06.02_PM.png" width="100%" />
  <img src="https://github.com/spyboy-productions/omnisci3nt/blob/main/image/Screenshot_2023-08-16_at_3.06.16_PM.png" width="100%" />
  <img src="https://github.com/spyboy-productions/omnisci3nt/blob/main/image/Screenshot_2023-08-16_at_3.06.42_PM.png" width="100%" />
  <img src="https://github.com/spyboy-productions/omnisci3nt/blob/main/image/Screenshot_2023-08-16_at_3.07.06_PM.png" width="100%" />
  <img src="https://github.com/spyboy-productions/omnisci3nt/blob/main/image/Screenshot_2023-08-16_at_3.07.26_PM.png" width="100%" />
</p>

---

<h4 align="center">⭐️ If this project helped you, please give it a star! ⭐️</h4>
