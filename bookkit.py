#!/usr/bin/env python3
"""
# ================================================================================
# AI Knowledge Pipeline
# ================================================================================
# 
# PURPOSE
# -------
# Converts books (PDF or EPUB) into a structured knowledge base that
# Claude Code can use as a mentor system. Run this on any book and it will
# automatically extract, classify, and organise the content into:
# 
#   - Topic skill files grouped by subject area
#   - Process/sequence files for multi-step workflows
#   - Obsidian-compatible markdown notes for your knowledge vault
#   - Chunk index JSON for RAG/embedding systems
#   - Clean markdown for full-text search
# 
# SUPPORTED DOMAINS
# -----------------
# Use --domain to select the right keyword set for your books:
# 
#   security        Penetration testing, vulnerabilities, exploit chains
#   sysadmin        Linux/Windows admin, networking, cloud, containers, CI/CD,
#                   databases, monitoring, scripting, storage, virtualisation
#   programming     Language fundamentals, algorithms, OOP, design patterns,
#                   testing, Python/JS/Java/C++/Rust/Go, web dev, concurrency
#   homesteading    Self-sufficiency, gardening, food preservation, livestock
#   cooking         Recipes, techniques, ingredients, equipment
#   history         Events, figures, periods, geography, movements
#   science         Biology, chemistry, physics, ecology, research methods
#   business        Strategy, finance, management, marketing, operations
#   health          Medicine, anatomy, fitness, mental health, nutrition
#   philosophy      Ethics, logic, metaphysics, epistemology, schools of thought
#   fiction         Plot, character, narrative, theme, genre analysis
#   general         Generic extraction — works for anything not listed above
# 
# Use --domain auto (default) to detect the domain from the book's content.
# 
# REQUIREMENTS
# ------------
# Python 3.8+
#   pip3 install ebooklib beautifulsoup4 pdfminer.six
# 
# No calibre required. PDF and EPUB are handled natively.
# 
# USAGE
# -----
# Single book:
#   python3 ai_knowledge_pipeline.py book.pdf
#   python3 ai_knowledge_pipeline.py book.epub
# 
# Specify domain explicitly:
#   python3 ai_knowledge_pipeline.py book.epub --domain homesteading
# 
# Entire folder of books:
#   python3 ai_knowledge_pipeline.py /path/to/books/
# 
# Specify custom output directory:
#   python3 ai_knowledge_pipeline.py book.pdf --output ~/knowledge_base
# 
# Combined single-file output (ideal for uploading to Claude):
#   python3 ai_knowledge_pipeline.py book.epub --combined
#   python3 ai_knowledge_pipeline.py ~/books/ --combined
# 
# OUTPUT STRUCTURE (default)
# --------------------------
# knowledge_brain/                ← root output directory
# ├── raw_markdown/               ← raw extracted text (useful for debugging)
# ├── clean_markdown/             ← cleaned, normalised markdown per book
# ├── topics/                     ← one file per topic category per book section
# │   ├── gardening_companion_planting.md
# │   ├── preservation_fermentation.md
# │   └── ...
# ├── sequences/                  ← multi-step processes / workflows extracted
# │   ├── composting_cycle.md
# │   └── ...
# ├── obsidian/                   ← drop into your Obsidian vault directly
# │   └── (one note per section)
# └── indexes/
#     ├── chunks.json             ← all text chunks for RAG/embedding search
#     └── book_index.json         ← metadata index across all processed books
# 
# COMBINED OUTPUT (--combined flag)
# ----------------------------------
# knowledge_brain/
# └── combined/
#     ├── self_sufficient_backyard.combined.md   ← one file per book
#     └── all_books.combined.md                  ← all books merged (multi-book runs)
# 
# TOPIC FILE FORMAT
# -----------------
# Each topic file has a YAML frontmatter block:
#   ---
#   title: Companion Planting Basics
#   source_book: self_sufficient_backyard
#   domain: homesteading
#   categories: [gardening]
#   tags: [gardening, companion planting, soil health]
#   ---
#   [section content]
# 
# This format is compatible with Claude Code skills and Obsidian.
# 
# HOW CLASSIFICATION WORKS
# -------------------------
# Each book section is scanned for topic keywords matching the selected domain.
# A section in a homesteading book containing "fermentation" and "canning" will
# be saved to topics/preservation_*.md. Sections that describe multi-step
# processes (sequences) are also saved separately in sequences/.
# 
# ADDING NEW DOMAINS OR EXTENDING EXISTING ONES
# ----------------------------------------------
# Edit the DOMAIN_KEYWORDS dict near the top of this file. Each domain is a
# dict of {category: [keywords]}. Add a new domain key or extend an existing one.
# 
# Example — adding a "photography" domain:
#   "photography": {
#       "composition":  ["rule of thirds", "framing", "leading lines"],
#       "exposure":     ["aperture", "shutter speed", "iso", "exposure triangle"],
#       "lighting":     ["golden hour", "diffuser", "reflector", "catchlight"],
#   }
# 
# ================================================================================
# """

import os
import re
import sys
import json
import argparse
import hashlib
from pathlib import Path
from collections import defaultdict


# ==============================================================================
# CONFIGURATION — edit these to customise behaviour
# ==============================================================================

# Root output directory (override with --output flag)
DEFAULT_OUTPUT = "knowledge_brain"

# Directory structure created inside the output root
DIRECTORIES = [
    "raw_markdown",
    "clean_markdown",
    "topics",
    "sequences",
    "obsidian",
    "indexes",
    "combined",
]

# Minimum section length in characters to be worth processing.
# Short sections (< 300 chars) are usually headers or transitions — skip them.
MIN_SECTION_LENGTH = 300

# Chunk size for RAG/embedding index (in characters, not tokens)
# 1200 chars ≈ 300 tokens — adjust for your embedding model's context window
CHUNK_SIZE = 1200

# ==============================================================================
# DOMAIN KEYWORD SETS
# ==============================================================================
# Each domain contains {category: [keywords]}.
# A section matching any keyword in a category's list is classified under
# that category. Categories are used in filenames and frontmatter.
#
# Add new domains or extend existing ones freely — nothing else needs changing.
# ==============================================================================

DOMAIN_KEYWORDS = {

    # ── Security / Penetration Testing ───────────────────────────────────────
    "security": {
        "xss":               ["xss", "cross-site scripting"],
        "sqli":              ["sql injection", "sqli", "blind injection"],
        "idor":              ["idor", "insecure direct object reference"],
        "ssrf":              ["ssrf", "server-side request forgery"],
        "rce":               ["remote code execution", "rce", "command injection"],
        "lfi":               ["lfi", "local file inclusion", "path traversal"],
        "ssti":              ["ssti", "server-side template injection"],
        "csrf":              ["csrf", "cross-site request forgery"],
        "auth-bypass":       ["authentication bypass", "mfa bypass", "2fa bypass"],
        "file-upload":       ["file upload", "unrestricted upload", "upload bypass"],
        "xxe":               ["xxe", "xml external entity"],
        "deserialization":   ["deserialization", "deserialisation", "pickle"],
        "jwt":               ["jwt", "json web token", "algorithm confusion"],
        "api":               ["graphql", "rest api", "api security", "bola"],
        "cloud":             ["aws", "s3 bucket", "iam", "azure", "imds"],
        "ad":                ["active directory", "kerberoasting", "bloodhound"],
        "linux-privesc":     ["sudo", "suid", "linux privilege escalation"],
        "windows-privesc":   ["windows privilege escalation", "winpeas"],
        "pivoting":          ["pivoting", "tunneling", "port forwarding"],
        "recon":             ["subdomain", "enumeration", "reconnaissance", "osint"],
        "prompt-injection":  ["prompt injection", "llm", "jailbreak", "system prompt"],
    },

    # ── Sysadmin / DevOps / Infrastructure ───────────────────────────────────
    # Covers: Linux & Windows admin, networking, cloud platforms, containers,
    # orchestration, CI/CD, databases, monitoring, scripting, storage,
    # virtualisation, identity, backup, and SRE practices.
    "sysadmin": {

        # ── Linux Administration ──────────────────────────────────────────────
        "linux-admin": [
            "systemd", "systemctl", "journalctl", "init system",
            "runlevel", "cron", "crontab", "at job", "anacron",
            "chmod", "chown", "chgrp", "umask", "acl", "setfacl", "getfacl",
            "inode", "hard link", "symlink", "symbolic link",
            "lvm", "logical volume", "physical volume", "volume group",
            "ext4", "xfs", "btrfs", "zfs", "filesystem",
            "mount", "fstab", "automount", "nfs mount",
            "swap", "swapfile", "swappiness",
            "kernel parameter", "sysctl", "proc filesystem", "/proc",
            "kernel module", "lsmod", "modprobe", "rmmod",
            "grub", "bootloader", "initramfs", "dracut",
            "selinux", "apparmor", "seccomp", "linux security",
            "ulimit", "limits.conf", "pam",
            "rpm", "yum", "dnf", "apt", "dpkg", "pacman", "snap", "flatpak",
            "package manager", "package repository",
            "useradd", "usermod", "userdel", "groupadd", "passwd",
            "su", "sudo", "sudoers", "visudo",
            "process management", "ps aux", "top", "htop", "kill", "killall",
            "nice", "renice", "ionice", "nohup", "screen", "tmux",
            "awk", "sed", "grep", "find", "xargs", "sort", "uniq", "cut",
            "rsync", "scp", "sftp", "ssh config",
            "file descriptor", "redirect", "pipe", "stdin", "stdout", "stderr",
            "strace", "lsof", "fuser",
        ],

        # ── Windows Administration ────────────────────────────────────────────
        "windows-admin": [
            "active directory", "ad ds", "domain controller", "group policy", "gpo",
            "powershell", "cmdlet", "get-", "set-", "new-", "remove-",
            "wmi", "cim", "win32_", "get-wmiobject",
            "registry", "regedit", "hklm", "hkcu", "reg query", "reg add",
            "windows service", "sc.exe", "services.msc",
            "task scheduler", "schtasks",
            "event log", "event viewer", "wevtutil", "get-eventlog",
            "iis", "internet information services", "appcmd", "web.config",
            "windows firewall", "netsh advfirewall", "wf.msc",
            "hyper-v", "virtual machine manager", "vmm",
            "wsus", "windows update", "windows server update",
            "dfs", "distributed file system", "dfsr",
            "winrm", "wsman", "remoting", "invoke-command",
            "kerberos", "ntlm", "ldap", "ldaps",
            "sysvol", "netlogon", "dcpromo",
            "robocopy", "xcopy", "icacls", "takeown",
            "perfmon", "resource monitor", "performance counter",
            "dns server", "dhcp server", "ipconfig", "nslookup",
            "smb", "cifs", "net use", "net share",
        ],

        # ── Networking ────────────────────────────────────────────────────────
        "networking": [
            "tcp/ip", "tcp", "udp", "icmp", "arp", "dhcp", "dns",
            "ip address", "ipv4", "ipv6", "cidr", "subnet", "subnetting",
            "default gateway", "routing table", "static route",
            "ospf", "bgp", "eigrp", "rip", "routing protocol",
            "vlan", "trunk", "access port", "dot1q", "802.1q",
            "nat", "pat", "snat", "dnat", "masquerade",
            "firewall", "iptables", "nftables", "pf", "ufw",
            "acl", "access control list", "packet filter",
            "load balancer", "haproxy", "nginx upstream", "keepalived",
            "vip", "virtual ip", "floating ip",
            "vpn", "openvpn", "wireguard", "ipsec", "ssl vpn",
            "network interface", "bonding", "teaming", "bridge",
            "tcpdump", "wireshark", "netstat", "ss", "traceroute", "mtr",
            "bandwidth", "qos", "traffic shaping", "tc command",
            "network namespace", "veth pair",
            "switch", "router", "hub", "access point",
            "802.11", "wifi", "wireless",
            "network troubleshooting", "packet capture", "latency", "jitter",
            "http", "https", "tls", "ssl", "certificate", "mTLS",
            "http/2", "http/3", "quic", "websocket",
            "proxy", "reverse proxy", "forward proxy", "transparent proxy",
        ],

        # ── Cloud Platforms ───────────────────────────────────────────────────
        "cloud": [
            # AWS
            "aws", "amazon web services", "ec2", "s3", "rds", "lambda",
            "iam", "vpc", "cloudfront", "route 53", "cloudwatch",
            "elastic beanstalk", "ecs", "eks", "fargate", "ecr",
            "cloudformation", "cdk", "sam", "elastic load balancer", "elb", "alb",
            "elasticache", "dynamodb", "sqs", "sns", "kinesis",
            "glacier", "ebs", "efs", "fsx",
            "security group", "nacl", "network acl", "aws config",
            "aws cli", "boto3", "assume role",
            # Azure
            "azure", "microsoft azure", "azure ad", "entra id",
            "azure vm", "azure blob", "azure sql", "azure functions",
            "arm template", "bicep", "azure devops",
            "aks", "azure kubernetes", "azure container",
            "virtual network", "vnet", "nsg", "azure firewall",
            "azure monitor", "log analytics", "application insights",
            # GCP
            "gcp", "google cloud", "gke", "cloud run", "cloud functions",
            "bigquery", "cloud storage", "cloud sql", "pub/sub",
            "compute engine", "gcloud", "cloud build",
            # General cloud
            "object storage", "block storage", "managed database",
            "serverless", "function as a service", "faas",
            "cloud native", "multi-cloud", "hybrid cloud",
            "cloud cost", "reserved instance", "spot instance",
            "autoscaling", "auto scaling group",
            "high availability", "fault tolerant", "region", "availability zone",
        ],

        # ── Containers & Orchestration ────────────────────────────────────────
        "containers": [
            "docker", "dockerfile", "docker compose", "docker swarm",
            "container image", "container registry", "layer", "overlay",
            "cgroup", "namespace", "pivot_root", "container runtime",
            "containerd", "cri-o", "podman", "buildah", "skopeo",
            "kubernetes", "k8s", "kubectl", "kubeconfig",
            "pod", "deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob",
            "service", "clusterip", "nodeport", "loadbalancer", "ingress",
            "configmap", "secret", "persistent volume", "pvc", "storage class",
            "namespace", "rbac", "service account", "role", "clusterrole",
            "helm", "chart", "values.yaml", "helmfile",
            "kustomize", "overlay", "patch",
            "resource limit", "request", "liveness probe", "readiness probe",
            "horizontal pod autoscaler", "hpa", "vpa", "cluster autoscaler",
            "node affinity", "taints", "tolerations",
            "network policy", "calico", "cilium", "flannel",
            "service mesh", "istio", "linkerd", "envoy",
            "openshift", "rancher", "k3s", "microk8s",
            "container security", "image scanning", "trivy", "falco",
            "oci", "open container initiative",
        ],

        # ── CI/CD & DevOps Tooling ────────────────────────────────────────────
        "cicd": [
            "ci/cd", "continuous integration", "continuous deployment",
            "continuous delivery", "pipeline", "build pipeline",
            "jenkins", "jenkinsfile", "github actions", "workflow yaml",
            "gitlab ci", ".gitlab-ci.yml", "gitlab runner",
            "circleci", "travis ci", "teamcity", "bamboo",
            "argocd", "flux", "gitops", "git ops",
            "artifact", "artifact registry", "nexus", "artifactory",
            "blue-green deployment", "canary deployment", "rolling update",
            "feature flag", "feature toggle",
            "sonarqube", "code quality", "static analysis", "sast",
            "unit test", "integration test", "end-to-end test", "test coverage",
            "makefile", "build script", "build tool",
            "infrastructure as code", "iac",
            "release management", "versioning", "semantic versioning", "semver",
            "webhook", "trigger", "runner", "agent",
        ],

        # ── Infrastructure as Code ────────────────────────────────────────────
        "iac": [
            "terraform", "hcl", "tfstate", "tf plan", "tf apply",
            "provider", "resource", "module", "data source", "output",
            "remote state", "s3 backend", "terraform cloud",
            "ansible", "playbook", "role", "task", "handler",
            "inventory", "host_vars", "group_vars", "vault",
            "jinja2", "template", "ansible galaxy",
            "puppet", "manifest", "catalog", "facter", "hiera",
            "chef", "cookbook", "recipe", "knife", "berkshelf",
            "saltstack", "salt", "pillar", "grain", "state file",
            "packer", "image build", "ami", "golden image",
            "vagrant", "vagrantfile",
            "pulumi", "crossplane",
            "idempotent", "desired state", "configuration drift",
            "infrastructure testing", "terratest", "kitchen",
        ],

        # ── Scripting & Automation ────────────────────────────────────────────
        "scripting": [
            "bash", "shell script", "sh script", "#!/bin/bash",
            "variable", "array", "associative array",
            "if statement", "for loop", "while loop", "case statement",
            "function", "return code", "exit code",
            "trap", "signal", "set -e", "set -x", "set -u", "pipefail",
            "heredoc", "here string",
            "regular expression", "regex", "grep -E", "egrep",
            "python script", "python3", "argparse", "subprocess",
            "os.path", "pathlib", "shutil", "tempfile",
            "requests", "paramiko", "fabric",
            "powershell script", "ps1", "profile", "execution policy",
            "pipeline object", "foreach-object", "where-object",
            "ruby", "rake", "gem",
            "perl", "go script", "lua",
            "make", "makefile", "cmake",
            "cron expression", "schedule",
        ],

        # ── Databases ─────────────────────────────────────────────────────────
        "databases": [
            # Relational
            "mysql", "mariadb", "postgresql", "postgres", "pg_",
            "sqlite", "oracle database", "sql server", "mssql",
            "sql query", "select", "insert", "update", "delete",
            "join", "inner join", "left join", "subquery",
            "index", "primary key", "foreign key", "constraint",
            "stored procedure", "trigger", "view", "materialised view",
            "transaction", "acid", "commit", "rollback", "savepoint",
            "replication", "master-slave", "primary-replica", "read replica",
            "sharding", "partitioning",
            "vacuum", "analyze", "explain plan", "query optimisation",
            "connection pool", "pgbouncer", "proxysql",
            "schema migration", "flyway", "liquibase", "alembic",
            # NoSQL
            "mongodb", "bson", "collection", "document store",
            "redis", "key-value", "cache", "ttl", "pub/sub",
            "elasticsearch", "kibana", "lucene", "index mapping",
            "cassandra", "keyspace", "column family",
            "dynamodb", "partition key", "sort key",
            "neo4j", "graph database", "cypher",
            "influxdb", "time series", "prometheus remote write",
            # General
            "database backup", "dump", "restore", "point in time recovery",
            "wal", "write ahead log", "binlog", "redo log",
            "high availability", "failover", "patroni", "galera",
        ],

        # ── Monitoring, Observability & Logging ───────────────────────────────
        "monitoring": [
            "prometheus", "alertmanager", "recording rule", "alert rule",
            "grafana", "dashboard", "panel", "data source",
            "metric", "gauge", "counter", "histogram", "summary",
            "label", "cardinality", "promql", "rate(", "increase(",
            "nagios", "zabbix", "icinga", "check_mk",
            "datadog", "newrelic", "dynatrace", "appdynamics",
            "apm", "application performance monitoring",
            "tracing", "distributed tracing", "jaeger", "zipkin", "opentelemetry",
            "span", "trace id", "context propagation",
            "log aggregation", "elk stack", "efk stack",
            "elasticsearch", "logstash", "filebeat", "fluentd", "fluent bit",
            "loki", "promtail", "log label",
            "splunk", "graylog",
            "syslog", "rsyslog", "syslog-ng", "journald",
            "uptime", "availability", "sla", "slo", "sli",
            "error budget", "burn rate",
            "alert", "pagerduty", "opsgenie", "victorops",
            "health check", "synthetic monitoring", "blackbox exporter",
            "snmp", "mibs",
        ],

        # ── Storage & Backup ──────────────────────────────────────────────────
        "storage": [
            "raid", "raid 0", "raid 1", "raid 5", "raid 6", "raid 10",
            "san", "storage area network", "iscsi", "fibre channel", "fc",
            "nas", "network attached storage", "nfs", "smb", "cifs",
            "object storage", "minio", "ceph", "glusterfs",
            "lvm", "pvs", "vgs", "lvs", "lvextend", "resize2fs",
            "zfs", "zpool", "zfs snapshot", "zvol",
            "btrfs", "snapshot", "subvolume", "send/receive",
            "disk quota", "inode exhaustion",
            "backup", "restore", "recovery", "rto", "rpo",
            "rsync", "duplicati", "bacula", "bareos", "amanda",
            "veeam", "commvault", "netbackup", "tsm",
            "snapshot", "incremental backup", "differential backup",
            "deduplication", "compression", "encryption at rest",
            "3-2-1 backup", "off-site backup", "cloud backup",
            "disaster recovery", "dr", "business continuity",
            "tape backup", "lto", "autoloader",
        ],

        # ── Virtualisation ────────────────────────────────────────────────────
        "virtualisation": [
            "hypervisor", "type 1", "type 2", "bare metal",
            "vmware", "vsphere", "esxi", "vcenter", "vsan", "nsx",
            "kvm", "qemu", "libvirt", "virsh", "virt-install",
            "xen", "citrix hypervisor",
            "hyper-v", "vmm", "virtual switch", "vm checkpoint",
            "virtual machine", "vm", "guest os", "host os",
            "snapshot", "clone", "template", "ovf", "ova",
            "memory balloon", "cpu pinning", "numa",
            "live migration", "vmotion", "storage vmotion",
            "ha cluster", "drs", "resource pool",
            "vagrant", "virtualbox", "vmware workstation",
            "nested virtualisation",
            "paravirtualisation", "hardware virtualisation", "vtx", "amd-v",
        ],

        # ── Identity, Certificates & Secrets ─────────────────────────────────
        "identity-secrets": [
            "ldap", "ldaps", "openldap", "active directory",
            "saml", "oauth2", "openid connect", "oidc",
            "sso", "single sign-on", "idp", "identity provider",
            "keycloak", "okta", "auth0", "azure ad",
            "rbac", "abac", "role-based access control",
            "mfa", "multi-factor authentication", "totp", "fido2", "yubikey",
            "x.509", "certificate", "ca", "certificate authority",
            "csr", "certificate signing request",
            "let's encrypt", "certbot", "acme",
            "tls certificate", "ssl certificate", "mutual tls",
            "pki", "public key infrastructure",
            "vault", "hashicorp vault", "secret engine", "dynamic secret",
            "aws secrets manager", "azure key vault",
            "encryption key", "kms", "key rotation",
            "service account", "api key", "token", "bearer token",
            "ssh key", "authorized_keys", "known_hosts", "ssh-keygen",
        ],

        # ── Web & Application Servers ─────────────────────────────────────────
        "web-servers": [
            "nginx", "nginx.conf", "server block", "location block",
            "upstream", "proxy_pass", "fastcgi",
            "apache", "httpd", "vhost", "virtual host", ".htaccess",
            "mod_rewrite", "mod_proxy", "mod_ssl",
            "caddy", "traefik", "envoy proxy",
            "ssl termination", "ssl offloading",
            "gzip compression", "brotli",
            "cache-control", "expires header", "etag",
            "rate limiting", "connection limiting",
            "keepalive", "worker process", "worker thread",
            "uwsgi", "gunicorn", "wsgi", "asgi", "uvicorn",
            "php-fpm", "fastcgi pool",
            "tomcat", "jboss", "wildfly", "glassfish",
            "reverse proxy", "cdn", "cloudflare",
            "cors", "content security policy", "hsts",
        ],

        # ── SRE / Reliability ─────────────────────────────────────────────────
        "sre": [
            "site reliability engineering", "sre",
            "slo", "service level objective",
            "sli", "service level indicator",
            "sla", "service level agreement",
            "error budget", "burn rate alert", "fast burn", "slow burn",
            "toil", "toil reduction", "automation",
            "incident", "incident response", "runbook", "playbook",
            "postmortem", "blameless postmortem", "root cause analysis",
            "mean time to recovery", "mttr",
            "mean time between failures", "mtbf",
            "chaos engineering", "chaos monkey", "game day",
            "capacity planning", "load testing", "stress testing",
            "graceful degradation", "circuit breaker", "bulkhead",
            "retry logic", "exponential backoff", "jitter",
            "four golden signals", "latency", "traffic", "errors", "saturation",
            "on-call", "escalation", "pagerduty",
            "change management", "change freeze",
        ],

        # ── Version Control & Collaboration ───────────────────────────────────
        "version-control": [
            "git", "git commit", "git push", "git pull", "git fetch",
            "git branch", "git merge", "git rebase", "git cherry-pick",
            "git stash", "git tag", "git log",
            "merge conflict", "rebase conflict",
            "pull request", "code review", "merge request",
            "github", "gitlab", "bitbucket", "gitea",
            "branching strategy", "gitflow", "trunk based development",
            "monorepo", "polyrepo",
            "submodule", "subtree",
            "pre-commit hook", "git hook",
            "code signing", "gpg sign",
            "svn", "subversion", "mercurial",
        ],

        # ── Security Hardening (sysadmin angle) ───────────────────────────────
        "hardening": [
            "cis benchmark", "stig", "security baseline",
            "patch management", "vulnerability scanning", "nessus", "openvas",
            "lynis", "oscap", "scap", "compliance scan",
            "fail2ban", "denyhosts", "brute force protection",
            "ssh hardening", "disable root login", "allowusers", "port knocking",
            "firewall rule", "least privilege", "principle of least privilege",
            "file integrity monitoring", "fim", "aide", "tripwire",
            "auditd", "audit rule", "ausearch", "aureport",
            "rootkit detection", "rkhunter", "chkrootkit",
            "encryption in transit", "encryption at rest",
            "certificate rotation", "key rotation",
            "network segmentation", "dmz", "zero trust",
            "waf", "web application firewall", "modsecurity",
            "intrusion detection", "ids", "ips", "snort", "suricata",
            "siem", "security information", "splunk", "qradar",
        ],
    },

    # ── Programming / Software Development ───────────────────────────────────
    # Covers: language fundamentals, paradigms, data structures, algorithms,
    # software design, testing, debugging, and major language ecosystems.
    # Distinct from "sysadmin" (which covers scripting as automation tooling)
    # and "security" (which covers exploitation) — this domain is for books
    # that teach programming itself: how to write and reason about code.
    "programming": {

        # ── Language Fundamentals ─────────────────────────────────────────────
        "fundamentals": [
            "variable", "data type", "integer", "float", "boolean", "string",
            "array", "list", "tuple", "dictionary", "hash map", "hashmap",
            "set data structure", "linked list", "stack", "queue",
            "if statement", "else clause", "switch statement", "case statement",
            "for loop", "while loop", "do-while", "loop iteration",
            "function", "method", "parameter", "argument", "return value",
            "recursion", "recursive function", "base case",
            "scope", "global variable", "local variable", "closure",
            "operator precedence", "type casting", "type coercion",
            "null", "none", "nil", "undefined",
            "comment", "syntax error", "compile error", "runtime error",
        ],

        # ── Object-Oriented & Paradigms ───────────────────────────────────────
        "paradigms": [
            "object-oriented programming", "oop", "class", "object instance",
            "inheritance", "polymorphism", "encapsulation", "abstraction",
            "interface", "abstract class", "constructor", "destructor",
            "method overriding", "method overloading", "super class", "base class",
            "composition over inheritance", "mixin", "trait",
            "functional programming", "pure function", "immutability",
            "first-class function", "higher-order function", "lambda",
            "map filter reduce", "currying", "monad", "functor",
            "procedural programming", "imperative programming",
            "declarative programming", "event-driven programming",
            "reactive programming", "observable", "stream processing",
            "concurrent programming", "parallel programming",
        ],

        # ── Data Structures & Algorithms ──────────────────────────────────────
        "algorithms": [
            "big o notation", "time complexity", "space complexity",
            "binary search", "linear search", "sorting algorithm",
            "bubble sort", "merge sort", "quick sort", "insertion sort", "heap sort",
            "binary tree", "binary search tree", "balanced tree", "avl tree", "red-black tree",
            "graph traversal", "breadth-first search", "depth-first search", "bfs", "dfs",
            "dijkstra", "shortest path", "minimum spanning tree",
            "dynamic programming", "memoization", "greedy algorithm",
            "divide and conquer", "backtracking",
            "hash table", "hash function", "collision resolution",
            "heap data structure", "priority queue", "trie",
            "graph data structure", "adjacency list", "adjacency matrix",
            "asymptotic analysis", "amortized analysis",
        ],

        # ── Software Design & Architecture ────────────────────────────────────
        "design": [
            "design pattern", "singleton pattern", "factory pattern", "observer pattern",
            "strategy pattern", "decorator pattern", "adapter pattern", "facade pattern",
            "solid principles", "single responsibility", "open-closed principle",
            "liskov substitution", "dependency inversion", "interface segregation",
            "dependency injection", "inversion of control",
            "software architecture", "microservices architecture", "monolith",
            "layered architecture", "hexagonal architecture", "clean architecture",
            "event-driven architecture", "message queue", "publish-subscribe",
            "domain-driven design", "ddd", "bounded context", "aggregate root",
            "mvc", "model-view-controller", "mvvm", "mvp pattern",
            "api design", "rest api design", "idempotency",
            "coupling", "cohesion", "technical debt", "code smell",
            "refactoring", "code review",
        ],

        # ── Testing & Debugging ───────────────────────────────────────────────
        "testing": [
            "unit test", "unit testing", "integration test", "end-to-end test",
            "test-driven development", "tdd", "behavior-driven development", "bdd",
            "test fixture", "mock object", "stub", "spy", "mocking",
            "assertion", "assert statement", "test case", "test suite",
            "pytest", "unittest", "junit", "jest", "mocha", "rspec",
            "code coverage", "test coverage",
            "debugger", "breakpoint", "stack trace", "step through",
            "print debugging", "logging statement",
            "exception handling", "try-except", "try-catch", "finally block",
            "error handling", "custom exception", "raise exception",
        ],

        # ── Python ────────────────────────────────────────────────────────────
        "python": [
            "python", "pythonic", "pep 8", "pep8", "list comprehension",
            "dict comprehension", "generator expression", "generator function", "yield",
            "decorator", "context manager", "with statement",
            "self parameter", "__init__", "dunder method", "magic method",
            "virtual environment", "venv", "pip install", "requirements.txt",
            "pandas dataframe", "numpy array", "django", "flask", "fastapi",
            "asyncio", "async def", "await keyword", "coroutine",
            "type hint", "type annotation", "mypy",
            "f-string", "walrus operator", "unpacking",
        ],

        # ── JavaScript / TypeScript ───────────────────────────────────────────
        "javascript": [
            "javascript", "typescript", "ecmascript", "es6", "es2015",
            "const keyword", "let keyword", "arrow function", "template literal",
            "promise", "async await", "callback function", "callback hell",
            "event loop", "microtask", "macrotask",
            "dom manipulation", "document object model",
            "node.js", "npm package", "package.json", "node modules",
            "react component", "jsx", "react hook", "usestate", "useeffect",
            "vue.js", "angular framework", "svelte",
            "express.js", "middleware function",
            "webpack", "babel transpiler", "bundler",
            "prototype chain", "this keyword", "hoisting",
        ],

        # ── Java / JVM Languages ──────────────────────────────────────────────
        "java": [
            "java", "jvm", "java virtual machine", "bytecode",
            "public class", "private method", "protected access",
            "interface implementation", "abstract method",
            "spring framework", "spring boot", "dependency injection",
            "maven", "gradle build", "pom.xml",
            "garbage collection", "heap memory", "stack memory",
            "generics", "wildcard type",
            "kotlin", "scala language", "groovy",
            "checked exception", "unchecked exception",
            "thread safety", "synchronized block", "concurrent collection",
        ],

        # ── C / C++ / Systems Languages ───────────────────────────────────────
        "systems-languages": [
            "c programming", "c++", "pointer arithmetic", "memory address",
            "malloc", "free function", "memory leak", "dangling pointer",
            "buffer overflow", "stack overflow error", "segmentation fault",
            "struct definition", "union type", "typedef",
            "header file", "compilation unit", "linker", "static linking",
            "rust language", "ownership model", "borrow checker", "lifetime",
            "cargo build", "trait implementation",
            "go language", "goroutine", "channel", "go routine",
            "zig language", "manual memory management",
        ],

        # ── Web Development ───────────────────────────────────────────────────
        "web-dev": [
            "html element", "css selector", "css flexbox", "css grid",
            "responsive design", "media query", "semantic html",
            "http request", "http response", "rest api endpoint",
            "graphql query", "graphql mutation", "graphql schema",
            "frontend framework", "backend framework", "full stack",
            "single page application", "spa", "server-side rendering", "ssr",
            "static site generator", "jamstack",
            "web accessibility", "wcag", "aria attribute",
            "browser devtools", "cross-origin resource sharing", "cors policy",
        ],

        # ── Version Control & Dev Workflow ────────────────────────────────────
        "dev-workflow": [
            "version control system", "git workflow", "feature branch",
            "code review process", "pull request review",
            "agile development", "scrum methodology", "sprint planning",
            "kanban board", "user story", "backlog grooming",
            "pair programming", "code pairing",
            "ide", "integrated development environment", "vs code", "intellij",
            "linter", "code formatter", "static type checking",
            "build automation", "package manager", "dependency management",
            "semantic versioning", "changelog",
        ],

        # ── Databases & Data (programming angle) ──────────────────────────────
        "data-handling": [
            "orm", "object-relational mapping", "query builder",
            "data validation", "schema design", "normalization",
            "serialization", "deserialization", "json parsing", "xml parsing",
            "api client", "sdk", "software development kit",
            "data structure design", "in-memory cache",
            "csv parsing", "data pipeline", "etl process",
        ],

        # ── Concurrency & Performance ──────────────────────────────────────────
        "concurrency": [
            "thread", "multithreading", "process vs thread",
            "race condition", "deadlock", "mutex", "semaphore", "lock contention",
            "atomic operation", "thread pool", "worker pool",
            "concurrency model", "parallelism", "asynchronous programming",
            "non-blocking io", "blocking call",
            "performance profiling", "benchmark", "optimization technique",
            "memory management", "garbage collector", "reference counting",
        ],
    },

    # ── Homesteading / Self-Sufficiency ──────────────────────────────────────
    "homesteading": {
        "gardening":         ["companion planting", "raised bed", "crop rotation", "soil amendment",
                              "mulching", "composting", "germination", "transplanting", "thinning",
                              "succession planting", "cover crop", "heirloom", "seed saving"],
        "preservation":      ["canning", "fermentation", "pickling", "dehydrating", "freeze drying",
                              "water bath", "pressure canning", "lacto-fermentation", "root cellar",
                              "smoking", "curing", "jam", "jelly", "chutney"],
        "livestock":         ["chicken", "hen", "rooster", "egg laying", "brooder", "goat", "pig",
                              "rabbit", "cattle", "bee", "beekeeping", "hive", "pasture", "forage"],
        "water":             ["rainwater", "grey water", "well", "cistern", "irrigation",
                              "drip irrigation", "water harvesting", "filtration", "spring"],
        "energy":            ["solar panel", "wind turbine", "off-grid", "battery bank",
                              "generator", "biogas", "wood gasifier", "inverter"],
        "building":          ["cob", "straw bale", "adobe", "timber frame", "earthship",
                              "natural building", "cordwood", "foundation", "insulation"],
        "foraging":          ["wild edible", "foraging", "mushroom", "medicinal herb",
                              "nettle", "elderberry", "dandelion", "identification"],
        "food-production":   ["harvest", "yield", "acre", "plot", "growing season",
                              "frost date", "hardiness zone", "planting calendar"],
        "cooking-skills":    ["sourdough", "bread baking", "cheese making", "butter",
                              "rendering", "lard", "tallow", "bone broth", "ferment"],
        "tools-equipment":   ["hand tool", "tractor", "tiller", "scythe", "chainsaw",
                              "wood stove", "rocket stove", "cold frame", "greenhouse"],
    },

    # ── Cooking & Food ───────────────────────────────────────────────────────
    "cooking": {
        "techniques":        ["sauté", "braise", "roast", "blanch", "poach", "deglaze",
                              "caramelise", "emulsify", "fold", "temper", "reduce"],
        "baking":            ["knead", "proof", "ferment", "gluten", "starter", "leaven",
                              "crumb", "crust", "pastry", "laminate", "blind bake"],
        "meat":              ["butchery", "marbling", "resting", "sear", "internal temperature",
                              "brine", "dry rub", "smoke", "cure", "render"],
        "vegetables":        ["blanching", "roasting", "pickling", "fermenting", "seasoning",
                              "al dente", "caramelising", "sweating"],
        "sauces":            ["béchamel", "velouté", "hollandaise", "mother sauce", "roux",
                              "reduction", "stock", "fond", "jus", "glaze"],
        "equipment":         ["cast iron", "dutch oven", "mandoline", "thermometer",
                              "immersion blender", "stand mixer", "sous vide"],
        "ingredients":       ["umami", "maillard", "acid", "fat", "salt", "bitterness",
                              "flavour profile", "seasoning", "spice blend"],
        "nutrition":         ["macronutrient", "protein", "carbohydrate", "fibre",
                              "vitamin", "mineral", "calorie", "glycemic"],
    },

    # ── History ───────────────────────────────────────────────────────────────
    "history": {
        "events":            ["battle", "revolution", "treaty", "declaration", "war",
                              "invasion", "siege", "coup", "rebellion", "uprising"],
        "figures":           ["king", "queen", "emperor", "general", "president",
                              "prime minister", "revolutionary", "philosopher"],
        "periods":           ["ancient", "medieval", "renaissance", "enlightenment",
                              "industrial revolution", "cold war", "world war"],
        "geography":         ["empire", "colony", "territory", "border", "trade route",
                              "migration", "settlement", "civilisation"],
        "society":           ["class", "feudal", "peasant", "aristocracy", "merchant",
                              "slavery", "suffrage", "reform", "movement"],
        "economics":         ["trade", "mercantilism", "capitalism", "currency",
                              "inflation", "depression", "taxation", "monopoly"],
        "religion":          ["church", "mosque", "temple", "crusade", "reformation",
                              "schism", "inquisition", "scripture", "clergy"],
        "technology":        ["invention", "printing press", "gunpowder", "steam engine",
                              "telegraph", "industrialisation", "agriculture"],
    },

    # ── Science ───────────────────────────────────────────────────────────────
    "science": {
        "biology":           ["cell", "dna", "protein", "evolution", "natural selection",
                              "ecosystem", "species", "organism", "photosynthesis"],
        "chemistry":         ["element", "compound", "molecule", "reaction", "catalyst",
                              "oxidation", "ph", "acid", "base", "bond"],
        "physics":           ["force", "energy", "momentum", "quantum", "relativity",
                              "wave", "particle", "gravity", "thermodynamics"],
        "ecology":           ["habitat", "biodiversity", "food chain", "carbon cycle",
                              "nitrogen cycle", "biome", "climate", "population"],
        "mathematics":       ["theorem", "proof", "equation", "function", "derivative",
                              "integral", "probability", "statistics", "matrix"],
        "research":          ["hypothesis", "experiment", "control group", "variable",
                              "peer review", "replication", "sample size", "methodology"],
    },

    # ── Business ──────────────────────────────────────────────────────────────
    "business": {
        "strategy":          ["competitive advantage", "market positioning", "swot",
                              "value proposition", "business model", "pivot", "disruption"],
        "finance":           ["revenue", "profit", "margin", "cash flow", "valuation",
                              "equity", "debt", "roi", "ebitda", "balance sheet"],
        "marketing":         ["brand", "customer acquisition", "funnel", "conversion",
                              "segmentation", "persona", "content marketing", "seo"],
        "management":        ["leadership", "delegation", "okr", "kpi", "agile",
                              "scrum", "project management", "team building"],
        "operations":        ["supply chain", "logistics", "inventory", "process",
                              "lean", "six sigma", "quality control", "efficiency"],
        "entrepreneurship":  ["startup", "bootstrapping", "venture capital", "angel investor",
                              "pitch", "mvp", "product-market fit", "scaling"],
    },

    # ── Health & Wellbeing ────────────────────────────────────────────────────
    "health": {
        "anatomy":           ["muscle", "bone", "organ", "nerve", "cardiovascular",
                              "respiratory", "digestive", "hormones", "immune"],
        "fitness":           ["strength training", "cardio", "flexibility", "mobility",
                              "hiit", "recovery", "progressive overload", "rep", "set"],
        "nutrition":         ["macronutrient", "micronutrient", "calorie deficit",
                              "protein intake", "gut health", "inflammation", "antioxidant"],
        "mental-health":     ["anxiety", "depression", "mindfulness", "meditation",
                              "stress", "sleep", "cognitive", "therapy", "resilience"],
        "medicine":          ["diagnosis", "treatment", "symptom", "condition", "chronic",
                              "acute", "prevention", "vaccination", "medication"],
        "herbal":            ["herb", "tincture", "infusion", "adaptogen", "phytochemical",
                              "traditional medicine", "remedy", "poultice"],
    },

    # ── Philosophy ───────────────────────────────────────────────────────────
    "philosophy": {
        "ethics":            ["moral", "virtue", "consequentialism", "deontology",
                              "utilitarianism", "justice", "rights", "duty"],
        "epistemology":      ["knowledge", "belief", "truth", "justification",
                              "empiricism", "rationalism", "scepticism", "a priori"],
        "metaphysics":       ["existence", "consciousness", "free will", "determinism",
                              "identity", "time", "causation", "reality"],
        "logic":             ["argument", "premise", "conclusion", "fallacy",
                              "deduction", "induction", "validity", "soundness"],
        "schools":           ["stoicism", "epicureanism", "platonism", "aristotle",
                              "kant", "nietzsche", "existentialism", "buddhism"],
        "political":         ["liberalism", "conservatism", "social contract", "sovereignty",
                              "democracy", "authority", "freedom", "equality"],
    },

    # ── Fiction / Literary Analysis ───────────────────────────────────────────
    "fiction": {
        "narrative":         ["point of view", "narration", "unreliable narrator",
                              "first person", "third person", "omniscient", "frame story"],
        "character":         ["protagonist", "antagonist", "arc", "motivation",
                              "foil", "round character", "flat character", "backstory"],
        "plot":              ["inciting incident", "rising action", "climax",
                              "falling action", "resolution", "foreshadowing", "flashback"],
        "theme":             ["theme", "motif", "symbol", "allegory", "metaphor",
                              "irony", "subtext", "moral"],
        "genre":             ["fantasy", "science fiction", "mystery", "thriller",
                              "romance", "horror", "literary fiction", "historical fiction"],
        "craft":             ["dialogue", "description", "pacing", "tension",
                              "show don't tell", "voice", "style", "prose"],
        "world-building":    ["setting", "world-building", "lore", "magic system",
                              "geography", "culture", "society", "mythology"],
    },

    # ── General (domain-agnostic fallback) ────────────────────────────────────
    "general": {
        "introduction":      ["introduction", "overview", "what is", "definition",
                              "background", "context", "fundamentals", "basics"],
        "process":           ["step", "process", "method", "procedure", "workflow",
                              "guide", "how to", "instructions", "technique"],
        "concepts":          ["principle", "concept", "theory", "framework", "model",
                              "approach", "strategy", "practice"],
        "resources":         ["resource", "tool", "material", "equipment", "supply",
                              "ingredient", "component", "requirement"],
        "troubleshooting":   ["problem", "issue", "error", "common mistake",
                              "troubleshoot", "fix", "solution", "avoid"],
        "examples":          ["example", "case study", "scenario", "illustration",
                              "sample", "demonstration", "instance"],
    },
}


# ==============================================================================
# SEQUENCE (MULTI-STEP PROCESS) DETECTION
# ==============================================================================
# Sections scoring SEQUENCE_THRESHOLD or more of these keywords are saved as
# sequences — the equivalent of "attack chains" in the security domain.
# Sequences represent multi-step workflows, cycles, or procedures.
#
# These are intentionally domain-neutral so they work across all domains.
# A homesteading book's "seed-to-harvest" workflow, a cooking book's
# multi-day fermentation process, and a security book's exploit chain all
# score against the same list.

SEQUENCE_KEYWORDS = [
    # Process / workflow language
    "step 1", "step 2", "first,", "second,", "third,",
    "next,", "then,", "finally,", "afterwards", "following this",
    "once you have", "before you", "after you", "as a result",

    # Cyclical / seasonal language (homesteading, ecology, history)
    "cycle", "rotation", "succession", "season", "phase", "stage",

    # Multi-part dependency language
    "in order to", "which allows", "this enables", "leading to",
    "resulting in", "followed by", "before moving", "build on",

    # Transformation / output language
    "produces", "yields", "harvest", "output", "result",
    "transform", "convert", "process", "refine",
]
SEQUENCE_THRESHOLD = 3  # number of keywords required to flag as a sequence


# ==============================================================================
# DOMAIN AUTO-DETECTION
# ==============================================================================

# Signature phrases that strongly identify a domain.
# Auto-detection samples the first 10,000 characters of a book and scores
# against these to pick the most likely domain.

DOMAIN_SIGNATURES = {
    "security":      ["vulnerability", "exploit", "payload", "pentest", "burp suite",
                      "sql injection", "xss", "reverse shell", "metasploit", "cve"],
    "sysadmin":      ["systemd", "systemctl", "nginx", "apache", "kubernetes", "docker",
                      "terraform", "ansible", "prometheus", "bash script", "cron",
                      "firewall", "iptables", "load balancer", "postgresql", "mysql",
                      "linux administration", "windows server", "active directory",
                      "deployment", "monitoring", "logging", "infrastructure"],
    "programming":   ["function", "variable", "class", "algorithm", "data structure",
                      "compiler", "syntax", "loop", "recursion", "object-oriented",
                      "python", "javascript", "source code", "debugging", "api",
                      "library", "framework", "git commit", "unit test", "design pattern"],
    "homesteading":  ["homestead", "self-sufficient", "off-grid", "raised bed",
                      "canning", "livestock", "compost", "heirloom seed", "root cellar"],
    "cooking":       ["recipe", "ingredient", "preheat", "tablespoon", "teaspoon",
                      "simmer", "bake", "sauté", "serves", "prep time"],
    "history":       ["century", "reign", "dynasty", "empire", "ancient", "medieval",
                      "world war", "revolution", "treaty", "chronicle"],
    "science":       ["hypothesis", "experiment", "species", "molecule", "equation",
                      "theory", "observation", "data", "peer-reviewed", "cell"],
    "business":      ["revenue", "strategy", "market", "customer", "profit",
                      "startup", "brand", "investment", "shareholder", "kpi"],
    "health":        ["symptom", "treatment", "exercise", "nutrition", "diagnosis",
                      "muscle", "cardiovascular", "therapy", "wellbeing", "supplement"],
    "philosophy":    ["virtue", "ethics", "consciousness", "truth", "knowledge",
                      "existence", "morality", "logic", "argument", "epistemology"],
    "fiction":       ["chapter one", "he said", "she said", "protagonist",
                      "narrator", "plot", "character", "dialogue", "setting"],
}


def detect_domain(text: str) -> str:
    """
    Auto-detect the most likely domain by scoring signature keywords
    against the first 10,000 characters of the extracted text.

    Returns the name of the best-matching domain, or 'general' if no
    domain scores above the threshold.
    """
    sample = text[:10_000].lower()
    scores = {}

    for domain, signatures in DOMAIN_SIGNATURES.items():
        scores[domain] = sum(1 for sig in signatures if sig in sample)

    best_domain = max(scores, key=scores.get)
    best_score  = scores[best_domain]

    # Require at least 2 matches to commit to a domain
    if best_score < 2:
        return "general"

    return best_domain


# ==============================================================================
# DEPENDENCY CHECKS
# ==============================================================================

def check_dependencies():
    """
    Verify required Python packages are installed before starting.
    Prints a clear install command if anything is missing.
    """
    missing = []

    try:
        import ebooklib        # EPUB parsing
    except ImportError:
        missing.append("ebooklib")

    try:
        from bs4 import BeautifulSoup  # HTML-to-text from EPUB
    except ImportError:
        missing.append("beautifulsoup4")

    try:
        from pdfminer.high_level import extract_text  # PDF text extraction
    except ImportError:
        missing.append("pdfminer.six")

    if missing:
        print("[!] Missing Python packages. Install with:")
        print(f"    pip3 install {' '.join(missing)}")
        sys.exit(1)


# ==============================================================================
# DIRECTORY SETUP
# ==============================================================================

def setup_directories(root: str):
    """
    Create the output directory structure.
    Safe to run multiple times — won't overwrite existing files.
    """
    for directory in DIRECTORIES:
        Path(root, directory).mkdir(parents=True, exist_ok=True)


# ==============================================================================
# TEXT EXTRACTION — PDF and EPUB handled natively, no calibre needed
# ==============================================================================

def extract_text_from_pdf(input_file: Path) -> str:
    """
    Extract raw text from a PDF using pdfminer.
    Handles encrypted/malformed PDFs gracefully.
    """
    from pdfminer.high_level import extract_text as pdf_extract
    from pdfminer.pdfdocument import PDFEncryptionError

    try:
        text = pdf_extract(str(input_file))
        if not text or len(text.strip()) < 100:
            print(f"  [!] PDF appears empty or image-only: {input_file.name}")
            return ""
        return text
    except PDFEncryptionError:
        print(f"  [!] PDF is encrypted, cannot extract: {input_file.name}")
        return ""
    except Exception as e:
        print(f"  [!] PDF extraction failed ({e}): {input_file.name}")
        return ""


def extract_text_from_epub(input_file: Path) -> str:
    """
    Extract raw text from an EPUB using ebooklib + BeautifulSoup.
    Preserves heading structure which is important for section splitting.
    """
    import ebooklib
    from ebooklib import epub
    from bs4 import BeautifulSoup

    try:
        book = epub.read_epub(str(input_file), options={"ignore_ncx": True})
    except Exception as e:
        print(f"  [!] EPUB read failed ({e}): {input_file.name}")
        return ""

    parts = []

    for item in book.get_items_of_type(ebooklib.ITEM_DOCUMENT):
        try:
            soup = BeautifulSoup(item.get_content(), "html.parser")

            # Convert headings to markdown before stripping HTML
            for tag in soup.find_all(["h1", "h2", "h3", "h4"]):
                level = int(tag.name[1])
                tag.replace_with(f"\n{'#' * level} {tag.get_text()}\n")

            # Extract plain text
            text = soup.get_text(separator="\n")
            parts.append(text)

        except Exception:
            continue

    return "\n\n".join(parts)


def extract_text(input_file: Path) -> str:
    """
    Route extraction to the correct handler based on file extension.
    Supports: .pdf, .epub, .txt, .md
    """
    suffix = input_file.suffix.lower()

    if suffix == ".pdf":
        return extract_text_from_pdf(input_file)
    elif suffix == ".epub":
        return extract_text_from_epub(input_file)
    elif suffix in (".txt", ".md"):
        return input_file.read_text(encoding="utf-8", errors="ignore")
    else:
        print(f"  [!] Unsupported format: {suffix} — skipping {input_file.name}")
        return ""


# ==============================================================================
# TEXT CLEANING
# ==============================================================================

def clean_text(text: str) -> str:
    """
    Normalise extracted text into clean markdown.

    What this removes:
    - Windows line endings
    - Runs of 3+ blank lines (collapsed to 2)
    - Standalone page numbers (a single number on its own line)
    - Copyright notices and "All rights reserved" lines
    - Null bytes and other non-printable characters

    What this preserves:
    - Markdown heading structure (# ## ###)
    - Code blocks
    - Bullet lists
    """
    # Normalise line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Remove null bytes and non-printable characters (except newlines/tabs)
    text = re.sub(r"[^\x09\x0a\x20-\x7e\x80-\xff]", "", text)

    # Remove standalone page numbers (whole line = just digits, optional spaces)
    text = re.sub(r"^\s*\d{1,4}\s*$", "", text, flags=re.MULTILINE)

    # Remove common boilerplate lines
    boilerplate = [
        r"^.*Copyright\s+©.*$",
        r"^.*All rights reserved.*$",
        r"^.*Table of Contents.*$",
        r"^.*www\.[a-z0-9.-]+\.[a-z]{2,}.*$",   # bare URLs in headers
    ]
    for pattern in boilerplate:
        text = re.sub(pattern, "", text, flags=re.IGNORECASE | re.MULTILINE)

    # Collapse 3+ consecutive blank lines into 2
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


# ==============================================================================
# SECTION SPLITTING
# ==============================================================================

def split_into_sections(text: str) -> list[dict]:
    """
    Split cleaned text into logical sections using markdown headings (# ##).

    For books with rich heading structure (EPUBs) this works immediately.
    For PDFs with few headings, falls back to splitting on "Chapter N" or
    "Part N" patterns commonly found in extracted PDF text.

    Returns a list of dicts:
        {
            "title":   "Section heading text",
            "content": "Full section text including heading"
        }

    Sections shorter than MIN_SECTION_LENGTH are discarded — they're
    usually transitional headings with no useful content.
    """

    def _make_sections(matches, text):
        """Convert a list of regex matches into section dicts."""
        results = []
        for i, match in enumerate(matches):
            start = match.start()
            end   = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            content = text[start:end].strip()

            if len(content) < MIN_SECTION_LENGTH:
                continue

            # Extract a clean title — skip if it looks like a code/path line
            raw_title = re.sub(r"^#+\s*", "", match.group(0)).strip()
            raw_title = re.sub(r"^(Chapter|Part|Section|Module)\s+\d+[:\s]*", "", raw_title, flags=re.IGNORECASE).strip()

            # Skip titles that look like file paths, shell commands, or URLs
            if re.search(r"^[/~\.\$]|https?://|::|==|--", raw_title):
                raw_title = "untitled_section"

            # Truncate very long "titles" — these are usually paragraphs, not headings
            if len(raw_title) > 100:
                raw_title = raw_title[:80].rsplit(" ", 1)[0] + "..."

            results.append({"title": raw_title or "untitled_section", "content": content})

        return results

    # ── Pass 1: Try markdown headings (# and ##) ──────────────────────────────
    pattern = r"(^#{1,2}\s+[A-Za-z][^\n]{3,}$)"
    raw_matches = list(re.finditer(pattern, text, re.MULTILINE))

    _SHELL_WORDS = {
        "cp", "mv", "rm", "ls", "cd", "mkdir", "chmod", "chown", "sudo",
        "apt", "pip", "git", "curl", "wget", "echo", "cat", "grep", "sed",
        "awk", "find", "tar", "zip", "ssh", "scp", "docker", "python",
        "python3", "ruby", "perl", "bash", "sh", "export", "source",
        "send", "open", "run", "execute", "executing", "install",
    }

    def _is_prose_heading(line: str) -> bool:
        """Return True only if this looks like a real document heading."""
        content = re.sub(r"^#+\s*", "", line).strip()

        if re.search(r"^[/~\.\$:=\-]|https?://|<|>|\|", content):
            return False

        words = re.findall(r"\b[a-zA-Z]{2,}\b", content)

        if len(words) < 3:
            return False

        first_word = words[0].lower() if words else ""
        if first_word in _SHELL_WORDS:
            return False

        shell_word_count = sum(1 for w in words if w.lower() in _SHELL_WORDS)
        if len(words) > 0 and shell_word_count / len(words) > 0.4:
            return False

        return True

    matches = [m for m in raw_matches if _is_prose_heading(m.group(0))]

    if len(matches) >= 5:
        return _make_sections(matches, text)

    # ── Pass 2: Try "Chapter N" / "Part N" ────────────────────────────────────
    chapter_pattern = r"(^(?:Chapter|Part|Section|Module|Unit|Lesson)\s+\d+[\s:–-]*.{0,80}$)"
    matches = list(re.finditer(chapter_pattern, text, re.MULTILINE | re.IGNORECASE))

    if len(matches) >= 2:
        modified_text = re.sub(
            chapter_pattern,
            lambda m: "## " + m.group(0).strip(),
            text,
            flags=re.MULTILINE | re.IGNORECASE,
        )
        matches = list(re.finditer(r"(^## .+$)", modified_text, re.MULTILINE))
        return _make_sections(matches, modified_text)

    # ── Pass 3: No structure found — treat whole book as one searchable block ─
    print("  [i] No heading structure detected — indexing as single section")
    return [{"title": "full_text", "content": text}]


# ==============================================================================
# CLASSIFICATION
# ==============================================================================

def classify_section(section_text: str, skill_keywords: dict) -> list[str]:
    """
    Identify which topic categories apply to a section.

    Scans the lowercased section text against the provided keyword dict.
    Returns a deduplicated list of matching category names.

    A section can match multiple categories — for example a homesteading
    section on "building a cold frame for year-round salad harvests" would
    match both 'building' and 'food-production'.
    """
    lower = section_text.lower()
    matches = set()

    for category, keywords in skill_keywords.items():
        for keyword in keywords:
            if keyword in lower:
                matches.add(category)
                break  # One match per category is enough

    return sorted(matches)


def is_sequence(section_text: str) -> bool:
    """
    Return True if the section describes a multi-step process or sequence.

    Checks how many SEQUENCE_KEYWORDS appear in the section.
    If the count meets SEQUENCE_THRESHOLD, it's flagged as a sequence.
    Domain-neutral: works for exploit chains, seed-to-harvest workflows,
    multi-day fermentation steps, historical cause-effect chains, etc.
    """
    lower = section_text.lower()
    score = sum(1 for kw in SEQUENCE_KEYWORDS if kw in lower)
    return score >= SEQUENCE_THRESHOLD


# ==============================================================================
# METADATA GENERATION
# ==============================================================================

def build_frontmatter(title: str, source_book: str, domain: str,
                      categories: list[str]) -> str:
    """
    Build a YAML frontmatter block for a topic or sequence file.

    The output is compatible with:
    - Claude Code skills (name + description fields are separate)
    - Obsidian (reads YAML frontmatter natively)
    - Jekyll/static site generators

    Format:
        ---
        title: Companion Planting Basics
        source_book: self_sufficient_backyard
        domain: homesteading
        categories: [gardening]
        tags: [homesteading, gardening]
        ---
    """
    tags = categories if categories else ["general"]
    tag_str = ", ".join(tags)

    return (
        f"---\n"
        f"title: {title}\n"
        f"source_book: {source_book}\n"
        f"domain: {domain}\n"
        f"categories: [{tag_str}]\n"
        f"tags: [{domain}, {tag_str}]\n"
        f"---\n\n"
    )


# ==============================================================================
# FILE SAVING HELPERS
# ==============================================================================

def safe_filename(text: str, max_length: int = 60) -> str:
    """
    Convert arbitrary text to a safe filename.
    Replaces any character that isn't alphanumeric, dash, or underscore.
    Truncates to max_length to avoid filesystem limits.
    """
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", text.lower())
    safe = re.sub(r"_+", "_", safe).strip("_")  # Collapse repeated underscores
    return safe[:max_length]


def save_topic_file(root: str, category: str, title: str,
                    content: str, source_book: str, domain: str):
    """
    Save a topic file into topics/<category>_<title>.md

    One file is created per (category, title) pair. If a section matches
    multiple categories, it gets saved into each — so a homesteading section
    about building a solar-powered greenhouse appears in both 'building'
    and 'energy'.
    """
    filename = f"{safe_filename(category)}_{safe_filename(title)}.md"
    output_path = Path(root, "topics", filename)

    frontmatter = build_frontmatter(title, source_book, domain, [category])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(frontmatter + content)


def save_sequence_file(root: str, title: str, content: str,
                       source_book: str, domain: str):
    """
    Save a multi-step process/sequence into sequences/<title>.md

    These files are saved separately because they describe workflows,
    cycles, or chains rather than isolated concepts.
    """
    filename = f"{safe_filename(title)}.md"
    output_path = Path(root, "sequences", filename)

    frontmatter = build_frontmatter(title, source_book, domain, ["sequence"])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(frontmatter + content)


def save_obsidian_note(root: str, title: str, content: str,
                       source_book: str, domain: str):
    """
    Save a note into obsidian/<title>.md for direct import into Obsidian.

    The note includes the source book and domain in the frontmatter so
    Obsidian's graph view can link related notes by book and domain.
    """
    filename = f"{safe_filename(title)}.md"
    output_path = Path(root, "obsidian", filename)

    # Avoid overwriting an identically named section from another book
    if output_path.exists():
        filename = f"{safe_filename(source_book)}_{safe_filename(title)}.md"
        output_path = Path(root, "obsidian", filename)

    frontmatter = build_frontmatter(title, source_book, domain, [])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(frontmatter + content)


# ==============================================================================
# CHUNKING
# ==============================================================================

def chunk_text(text: str, chunk_size: int = CHUNK_SIZE) -> list[str]:
    """
    Split text into fixed-size chunks for embedding/RAG systems.

    Splits on word boundaries to avoid cutting words mid-way.
    Each chunk is approximately chunk_size characters.

    For use with:
    - OpenAI text-embedding-3-small
    - sentence-transformers
    - Any vector database (Chroma, Pinecone, Qdrant, etc.)
    """
    words = text.split()
    chunks = []
    current_words = []
    current_size  = 0

    for word in words:
        current_words.append(word)
        current_size += len(word) + 1  # +1 for the space

        if current_size >= chunk_size:
            chunks.append(" ".join(current_words))
            current_words = []
            current_size  = 0

    if current_words:
        chunks.append(" ".join(current_words))

    return chunks


# ==============================================================================
# INDEX BUILDING
# ==============================================================================

def load_existing_index(root: str) -> list[dict]:
    """Load the existing chunk index if it exists, for incremental updates."""
    index_path = Path(root, "indexes", "chunks.json")
    if index_path.exists():
        with open(index_path, encoding="utf-8") as f:
            return json.load(f)
    return []


def save_chunk_index(root: str, all_chunks: list[dict]):
    """
    Append new chunks to the main chunk index at indexes/chunks.json.

    Each chunk entry:
        {
            "id":          "md5 hash of chunk text",
            "source_book": "book filename stem",
            "domain":      "detected or specified domain",
            "text":        "chunk text content"
        }

    The id field lets you deduplicate chunks if the same book is processed
    more than once. Existing chunks with the same id are not duplicated.
    """
    existing = load_existing_index(root)
    existing_ids = {entry["id"] for entry in existing}

    new_entries = []
    for chunk in all_chunks:
        chunk_id = hashlib.md5(chunk["text"].encode()).hexdigest()
        if chunk_id not in existing_ids:
            new_entries.append({
                "id":          chunk_id,
                "source_book": chunk["source_book"],
                "domain":      chunk.get("domain", "general"),
                "text":        chunk["text"],
            })

    combined = existing + new_entries

    index_path = Path(root, "indexes", "chunks.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, ensure_ascii=False)

    return len(new_entries)


def update_book_index(root: str, book_stem: str, stats: dict):
    """
    Update the book-level metadata index at indexes/book_index.json.

    Tracks which books have been processed and their statistics:
        {
            "bookname": {
                "domain":      "homesteading",
                "sections":    42,
                "topic_files": 18,
                "sequences":   3,
                "chunks":      156,
                "categories":  ["gardening", "preservation", "livestock", ...]
            }
        }
    """
    index_path = Path(root, "indexes", "book_index.json")

    if index_path.exists():
        with open(index_path, encoding="utf-8") as f:
            index = json.load(f)
    else:
        index = {}

    index[book_stem] = stats

    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)


# ==============================================================================
# COMBINED SINGLE-FILE OUTPUT
# ==============================================================================

def save_combined_markdown(root: str, book_stem: str, domain: str,
                           sections: list[dict], stats: dict) -> Path:
    """
    Write all sections of a single book into one consolidated .md file.

    Structure of the combined file:
        # <Book Title>
        (YAML metadata block)

        ## Table of Contents
        - [Section Title](#anchor) [category tags]
        ...

        ---
        ## Section Title
        **Categories:** gardening, food-production
        **Sequence:** yes / no

        <section content>

        ---
        (repeat for all sections)

    Returns the path of the written file so callers can report it.
    """
    from datetime import datetime

    output_path = Path(root, "combined", f"{book_stem}.combined.md")

    categories_all = stats.get("categories", [])
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = []

    # ── File header ────────────────────────────────────────────────────────────
    lines.append(f"# {book_stem.replace('_', ' ').title()}")
    lines.append("")
    lines.append("```yaml")
    lines.append(f"source_book: {book_stem}")
    lines.append(f"domain: {domain}")
    lines.append(f"processed: {now}")
    lines.append(f"sections: {stats.get('sections', len(sections))}")
    lines.append(f"sequences: {stats.get('sequences', 0)}")
    lines.append(f"categories: [{', '.join(categories_all)}]")
    lines.append("```")
    lines.append("")

    # ── Table of contents ─────────────────────────────────────────────────────
    lines.append("## Table of Contents")
    lines.append("")
    for i, section in enumerate(sections, 1):
        title  = section["title"]
        cats   = section.get("categories", [])
        anchor = re.sub(r"[^a-z0-9-]", "", title.lower().replace(" ", "-"))
        tag_str = f" `{'` `'.join(cats)}`" if cats else ""
        lines.append(f"{i}. [{title}](#{anchor}){tag_str}")
    lines.append("")

    # ── Sections ──────────────────────────────────────────────────────────────
    for section in sections:
        title   = section["title"]
        content = section["content"]
        cats    = section.get("categories", [])
        is_seq  = section.get("is_sequence", False)

        lines.append("---")
        lines.append("")
        lines.append(f"## {title}")
        lines.append("")

        meta_parts = []
        if cats:
            meta_parts.append(f"**Categories:** {', '.join(cats)}")
        if is_seq:
            meta_parts.append("**Sequence:** yes")
        if meta_parts:
            lines.append("  ".join(meta_parts))
            lines.append("")

        # Strip the leading heading from content if it duplicates the title
        # (happens when section splitting keeps the heading line in content)
        body = re.sub(r"^#{1,4}\s+" + re.escape(title) + r"\s*\n", "", content, count=1)
        lines.append(body.strip())
        lines.append("")

    # ── Write ─────────────────────────────────────────────────────────────────
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def merge_combined_files(root: str, book_stems: list[str]) -> Path:
    """
    Merge all per-book combined files into a single all_books.combined.md.
    Used when processing multiple books in one run.

    Each book's content is wrapped in a top-level section so the merged
    file is still navigable. The per-book files are kept alongside it.
    """
    output_path = Path(root, "combined", "all_books.combined.md")

    lines = ["# All Books — Combined Knowledge Base", ""]
    lines.append(f"**Books included:** {len(book_stems)}")
    lines.append("")

    for stem in book_stems:
        lines.append(f"- [{stem.replace('_', ' ').title()}](#{stem})")
    lines.append("")

    for stem in book_stems:
        per_book = Path(root, "combined", f"{stem}.combined.md")
        if not per_book.exists():
            continue
        book_content = per_book.read_text(encoding="utf-8")
        lines.append(f"---")
        lines.append("")
        # Re-indent the book's top-level heading as a second-level heading
        # so the merged file has a single H1 at the top
        book_content = re.sub(r"^# ", "## ", book_content, count=1, flags=re.MULTILINE)
        lines.append(book_content)
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path




def process_book(input_file: Path, root: str, domain_override: str = "auto",
                 combined: bool = False) -> dict:
    """
    Full pipeline for a single book file.

    Steps:
        1. Extract raw text (PDF or EPUB)
        2. Save raw text to raw_markdown/
        3. Auto-detect domain (or use domain_override)
        4. Clean and normalise the text
        5. Save clean text to clean_markdown/
        6. Split into sections by heading
        7. Classify each section by topic category
        8. Save topic files for each matching category  [skipped with --combined]
        9. Save sequence files for multi-step processes [skipped with --combined]
        10. Save Obsidian notes                         [skipped with --combined]
        11. Build text chunks for embeddings
        12. Update the chunk index
        13. Write combined .md file                     [only with --combined]

    Returns a stats dict for the book index. When combined=True the dict
    also contains a 'combined_path' key with the output file path.
    """

    book_stem = input_file.stem
    print(f"\n[→] Processing: {input_file.name}")

    # ── Step 1: Extract ──────────────────────────────────────────────────────
    raw_text = extract_text(input_file)

    if not raw_text.strip():
        print(f"  [!] No text extracted — skipping.")
        return {}

    # ── Step 2: Save raw text ────────────────────────────────────────────────
    raw_path = Path(root, "raw_markdown", f"{book_stem}.raw.md")
    raw_path.write_text(raw_text, encoding="utf-8")

    # ── Step 3: Detect or apply domain ───────────────────────────────────────
    if domain_override == "auto":
        domain = detect_domain(raw_text)
        print(f"  [i] Domain auto-detected: {domain}")
    else:
        domain = domain_override
        print(f"  [i] Domain: {domain} (specified)")

    # Get the keyword set for the domain, falling back to 'general'
    skill_keywords = DOMAIN_KEYWORDS.get(domain, DOMAIN_KEYWORDS["general"])

    # ── Step 4 & 5: Clean and save ───────────────────────────────────────────
    clean = clean_text(raw_text)
    clean_path = Path(root, "clean_markdown", f"{book_stem}.clean.md")
    clean_path.write_text(clean, encoding="utf-8")

    # ── Step 6: Split into sections ───────────────────────────────────────────
    sections = split_into_sections(clean)
    print(f"  [✓] {len(sections)} sections extracted")

    # ── Steps 7-11: Process each section ─────────────────────────────────────
    all_chunks        = []
    topic_file_count  = 0
    sequence_count    = 0
    all_categories    = set()
    annotated_sections = []   # used for combined output

    for section in sections:
        title   = section["title"]
        content = section["content"]

        # Classify
        categories = classify_section(content, skill_keywords)
        all_categories.update(categories)

        # Flag sequences
        seq = is_sequence(content)
        if seq:
            sequence_count += 1

        # Annotate section for combined output (always, even in normal mode)
        annotated_sections.append({
            "title":       title,
            "content":     content,
            "categories":  categories,
            "is_sequence": seq,
        })

        if not combined:
            # Save topic files (one per matching category)
            for category in categories:
                save_topic_file(root, category, title, content, book_stem, domain)
                topic_file_count += 1

            # Save sequence file if this section describes a multi-step process
            if seq:
                save_sequence_file(root, title, content, book_stem, domain)

            # Save Obsidian note
            save_obsidian_note(root, title, content, book_stem, domain)
        else:
            topic_file_count += len(categories)  # count for stats even if not written

        # Generate chunks with source metadata attached
        for chunk_text_piece in chunk_text(content):
            all_chunks.append({
                "source_book": book_stem,
                "domain":      domain,
                "text":        chunk_text_piece,
            })

    # ── Step 12: Update chunk index ───────────────────────────────────────────
    new_chunk_count = save_chunk_index(root, all_chunks)

    # ── Summary ───────────────────────────────────────────────────────────────
    stats = {
        "domain":       domain,
        "sections":     len(sections),
        "topic_files":  topic_file_count,
        "sequences":    sequence_count,
        "chunks":       new_chunk_count,
        "categories":   sorted(all_categories),
    }

    if combined:
        combined_path = save_combined_markdown(root, book_stem, domain,
                                               annotated_sections, stats)
        stats["combined_path"] = str(combined_path)
        print(f"  [✓] Combined file: {combined_path}")
    else:
        print(f"  [✓] {topic_file_count} topic files saved")
        print(f"  [✓] {sequence_count} sequence files saved")

    print(f"  [✓] {new_chunk_count} new chunks indexed")
    print(f"  [✓] Categories: {', '.join(sorted(all_categories)) or 'none matched'}")

    update_book_index(root, book_stem, stats)

    return stats


# ==============================================================================
# MULTI-FILE PROCESSING
# ==============================================================================

def find_books(path: Path) -> list[Path]:
    """
    Find all supported book files at a given path.

    If path is a file, return it (if supported).
    If path is a directory, recursively find all .pdf and .epub files.
    """
    supported = {".pdf", ".epub", ".txt", ".md"}

    if path.is_file():
        if path.suffix.lower() in supported:
            return [path]
        else:
            print(f"[!] Unsupported file type: {path.suffix}")
            sys.exit(1)

    if path.is_dir():
        books = []
        for ext in supported:
            books.extend(sorted(path.rglob(f"*{ext}")))
        return books

    print(f"[!] Path not found: {path}")
    sys.exit(1)


# ==============================================================================
# ENTRY POINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="ai_knowledge_pipeline",
        description=(
            "Convert books (PDF/EPUB/TXT) of any genre into a structured knowledge base "
            "for Claude Code mentor systems, Obsidian vaults, and RAG pipelines."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
SUPPORTED DOMAINS
  {", ".join(sorted(DOMAIN_KEYWORDS.keys()))}

EXAMPLES
  Auto-detect domain (recommended):
    python3 ai_knowledge_pipeline.py mybook.epub

  Specify domain explicitly:
    python3 ai_knowledge_pipeline.py self_sufficient_backyard.epub --domain homesteading
    python3 ai_knowledge_pipeline.py hackingapis.pdf --domain security
    python3 ai_knowledge_pipeline.py history_of_rome.pdf --domain history
    python3 ai_knowledge_pipeline.py kubernetes_in_action.pdf --domain sysadmin
    python3 ai_knowledge_pipeline.py ansible_for_devops.epub --domain sysadmin
    python3 ai_knowledge_pipeline.py ~/Books/sysadmin/ --domain sysadmin
    python3 ai_knowledge_pipeline.py clean_code.epub --domain programming
    python3 ai_knowledge_pipeline.py effective_python.pdf --domain programming

  Combined single-file output (upload directly to Claude, no file limit worries):
    python3 ai_knowledge_pipeline.py mybook.epub --combined
    python3 ai_knowledge_pipeline.py ~/Books/ --combined

  Process an entire folder (mixed genres — each book auto-detected):
    python3 ai_knowledge_pipeline.py ~/Documents/Books/

  Custom output directory:
    python3 ai_knowledge_pipeline.py mybook.pdf --output ~/my_knowledge_base

  Check what was extracted:
    cat knowledge_brain/indexes/book_index.json

OUTPUT (default)
  knowledge_brain/topics/      — topic files grouped by subject area
  knowledge_brain/sequences/   — multi-step processes and workflows
  knowledge_brain/obsidian/    — drop directly into Obsidian vault
  knowledge_brain/indexes/     — JSON indexes for RAG/search
  knowledge_brain/clean_markdown/ — full cleaned text per book

OUTPUT (--combined)
  knowledge_brain/combined/<bookname>.combined.md  — one file per book
  knowledge_brain/combined/all_books.combined.md   — merged (multi-book runs)
        """,
    )

    parser.add_argument(
        "input",
        help="Path to a book file (.pdf / .epub / .txt / .md) or a folder of books",
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        metavar="DIR",
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )

    parser.add_argument(
        "--domain",
        default="auto",
        metavar="DOMAIN",
        choices=list(DOMAIN_KEYWORDS.keys()) + ["auto"],
        help=(
            "Knowledge domain for keyword classification. "
            f"Options: {', '.join(sorted(DOMAIN_KEYWORDS.keys()))}, auto. "
            "Default: auto (detects from book content)"
        ),
    )

    parser.add_argument(
        "--combined",
        action="store_true",
        default=False,
        help=(
            "Write all sections into a single .md file per book instead of "
            "individual topic/sequence/obsidian files. When processing multiple "
            "books, also creates all_books.combined.md merging everything together. "
            "Ideal for uploading directly to Claude without hitting file limits."
        ),
    )

    args = parser.parse_args()

    # Dependency check
    check_dependencies()

    # Setup output directories
    setup_directories(args.output)

    # Find books to process
    input_path = Path(args.input)
    books = find_books(input_path)

    if not books:
        print(f"[!] No supported book files found at: {input_path}")
        sys.exit(1)

    print(f"\n[+] Found {len(books)} book(s) to process")
    print(f"[+] Domain: {args.domain}")
    print(f"[+] Mode: {'combined single-file' if args.combined else 'structured multi-file (default)'}")
    print(f"[+] Output directory: {Path(args.output).resolve()}\n")

    # Process each book
    total_topics    = 0
    total_sequences = 0
    total_chunks    = 0
    domains_seen    = set()
    processed_stems = []

    for book in books:
        stats = process_book(book, args.output, args.domain, combined=args.combined)
        if stats:
            total_topics    += stats.get("topic_files", 0)
            total_sequences += stats.get("sequences",   0)
            total_chunks    += stats.get("chunks",      0)
            domains_seen.add(stats.get("domain", "general"))
            processed_stems.append(book.stem)

    # Merge all combined files into one if processing multiple books
    if args.combined and len(processed_stems) > 1:
        merged_path = merge_combined_files(args.output, processed_stems)
        print(f"\n[✓] All books merged → {merged_path}")

    # Final summary
    print(f"\n{'='*60}")
    print(f"  Pipeline complete")
    print(f"  Books processed:  {len(books)}")
    print(f"  Domains used:     {', '.join(sorted(domains_seen))}")
    if args.combined:
        combined_dir = Path(args.output, "combined")
        print(f"  Combined files:   {combined_dir}/")
        if len(processed_stems) > 1:
            print(f"  Merged file:      {combined_dir}/all_books.combined.md")
    else:
        print(f"  Topic files:      {total_topics}")
        print(f"  Sequences:        {total_sequences}")
    print(f"  Chunks indexed:   {total_chunks}")
    print(f"  Output:           {Path(args.output).resolve()}")
    print(f"{'='*60}\n")

    index_path = Path(args.output, "indexes", "book_index.json")
    print(f"  Review what was classified:")
    print(f"    cat {index_path}\n")


if __name__ == "__main__":
    main()
