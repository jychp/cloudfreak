# CloudFreak
Serverless Pentest tools using Cloudflare free account.

![CloudFreak](data/cloudfreak.jpeg)

---

## 📒 Table of Contents
- [📒 Table of Contents](#-table-of-contents)
- [📍 Overview](#-overview)
- [📂 Project Structure](#project-structure)
- [🧩 Tools](#tools)
- [🚀 Getting Started](#-getting-started)
- [🗺 Roadmap](#-roadmap)
- [🤝 Contributing](#-contributing)

---

## 📍 Overview

This project uses various Cloudflare components (accessible with a free account) to offer useful capabilities for a penetration test.

The goal is to provide an easily and quickly deployable serverless platform for conducting a pentest.

---

## 📂 Project Structure

The `/infra` folder contains all the Terraform files needed to deploy the infrastructure on the Cloudflare side.

The various tools are accessible through Python scripts at the root of the repository.


---

## 🧩 Tools

| Feature                | Description                           |
| ---------------------- | ------------------------------------- |
| cf-scanner             | TCP port scanner using Cloudflare Workers |

---

## 🚀 Getting Started

### ✔️ Prerequisites

Before you begin, ensure that you have the following prerequisites installed:
> - `poetry`
> - `terraform`

### 📦 Installation

1. Create a Cloudflare account

2. Get your Cloudflare Account ID
> https://dash.cloudflare.com/<CLOUDFLARE_ACCOUNT_ID>/

3. Create a [Cloudflare API Key](https://dash.cloudflare.com/profile/api-tokens) with following scopes:
> - Account - Workers Scripts:Edit

4. Generate a random secret that will be used to authenticate your calls (you can use pwgen for instance)

5. Create a `terraform.tfvars` file in `infra/`:
```
cloudflare_api_token  = "<CHANGE_ME>"
cloudflare_account_id = "<CHANGE_ME>"
cloudfreak_apikey     = "<CHANGE_ME>"
```

6. Create your resources in Cloudflare using terraform:
```sh
terraform init
terraform plan
terraform apply
```

7. Go to your Cloudflare dashboard to get your worker URL (you will need to enable it)
> https://dash.cloudflare.com/<ACCOUNT_ID>/workers/services/view/cf-scanner/production/settings

### 🎮 Using cf-scanner

cf-scanner will make a `POST` request to a dedicated worker that perform TCP connection to scan targets. Targets are split among multiple workers to increase speed.

Known limitations:
- Can only scan TCP ports
- Port 25 is forbidden
- You can not scan Cloudflare IPs

example:
> poetry run python3 scanner.py <IP> -p 21,22,80,443 -w <WORKER_URL> -v --output output.json --apikey <APIKEY>

Les cibles du scans sont passées en positionnal argument et peuvent être un hostname, une IP ou un CIDR

La commande accepte les options suivantes

| Option | Type | Description |
| ------ | ---- | ----------- |
| -v     | flag | Verbose logging, display debug messages |
| -p     | int (mandatory) | single port (22), comma separated list (21,22), range (21-22) |
| --apikey | string (mandatory)| CloudFreak APIKEY defined during startup |
| -w     | string (mandatory) | Url of the Cloudflare Worker (full url starting with https://)
| -o     | path | Path to a JSON file for detailed output |
| -i     | path | Path of a list of target (one target per line)
| --parallelism | int | Number of concurrent workers (default: 5) |
| --data | string | Data sent to the foreign service (default: `GET / HTTP/1.1\r\n\r\n`) |
| --timeout | int | Timeout in ms for host scanning (default: 2000) |
| --ssl | flag | Enable SSL on TCP connect |

---

## 🗺 Roadmap

> - [ ] improve banner grabbing

---

## 🤝 Contributing

Feel free to contribute !
