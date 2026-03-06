# PrestaShop Security Groups -- Configuration Reference

**Project:** Architecting a Secure 2-Tier E-Commerce Infrastructure on AWS  
**Author:** John Ejoke Oghenekewe | Cybersecurity Analyst | SOC Engineer  
**Region:** eu-north-1 (Europe Stockholm)  
**VPC:** vpc-0593fa8a0cec6506a (Default VPC, 3 Subnets, 3 Availability Zones)

---

## Security Architecture Overview

This project enforces a Zero-Trust perimeter between the web tier and the data tier using Security Group Chaining. Neither tier trusts the other by default. Traffic is permitted only on the specific ports required for the application to function, and the database tier has no public internet exposure whatsoever.

The key engineering decision is that the database security group does not reference an IP address range as its inbound source. It references the web security group ID directly. This means the trust relationship is between the security groups, not the IP addresses. If the EC2 instance is replaced, scaled, or its IP changes, the rule remains valid. No manual update required.

---

## Security Group 1: PrestaShop-Web-SG

**Security Group ID:** sg-06bfb5512c584778b  
**Name:** PrestaShop-Web-SG  
**Description:** Perimeter Security Group for PrestaShop Application Server. Allows public HTTP/HTTPS traffic and restricted SSH access for administrative maintenance.  
**Role:** Public-facing perimeter firewall for the EC2 web tier  
**Attached to:** EC2 instance (PrestaShop web server, t3.micro)

### Inbound Rules

| Type | Protocol | Port | Source | Rationale |
|---|---|---|---|---|
| HTTP | TCP | 80 | 0.0.0.0/0 | Customer web traffic. Open to the world so the storefront is publicly accessible. |
| SSH | TCP | 22 | 102.221.237.130/32 | Administrative access. Locked to management IP only. SSH open to 0.0.0.0/0 is a brute-force invitation. |

### Outbound Rules

| Type | Protocol | Port | Destination | Rationale |
|---|---|---|---|---|
| All traffic | All | All | 0.0.0.0/0 | Default AWS outbound rule. The instance needs to reach the internet for package downloads, RDS communication, and outbound application requests. |

### Engineering Notes

SSH is restricted to a single /32 CIDR. This is not a convenience shortcut. It is a deliberate control that eliminates the entire attack surface of internet-facing SSH. Any attempt to reach Port 22 from any IP outside that /32 is dropped at the security group layer before it reaches the instance. If the management IP changes, the rule is updated. This is preferable to leaving SSH open.

HTTP on Port 80 is intentionally open while HTTPS on Port 443 is not configured. This deployment does not yet have an SSL certificate. Adding ACM-issued TLS and forcing HTTP to HTTPS redirection through an Application Load Balancer is documented in the future enhancements section of the README.

---

## Security Group 2: PrestaShop-DB-SG

**Security Group ID:** sg-0c85b5be41b4af149  
**Name:** PrestaShop-DB-SG  
**Description:** Internal Data Layer Security Group. Enforces network isolation by permitting MySQL traffic exclusively from the PrestaShop-Web-SG via security group chaining.  
**Role:** Private data tier firewall for the RDS MySQL instance  
**Attached to:** RDS instance (prestashop-database, MySQL 8.4)

### Inbound Rules

| Type | Protocol | Port | Source | Rationale |
|---|---|---|---|---|
| MYSQL/Aurora | TCP | 3306 | sg-06bfb5512c584778b | Database access locked exclusively to the web tier security group. No other source can reach this port. |

### Outbound Rules

| Type | Protocol | Port | Destination | Rationale |
|---|---|---|---|---|
| All traffic | All | All | 0.0.0.0/0 | Default AWS outbound rule. RDS needs outbound for maintenance and AWS internal communications. |

### Engineering Notes

The source for the MySQL inbound rule is `sg-06bfb5512c584778b`, the security group ID of PrestaShop-Web-SG, not an IP address or CIDR range. This is Security Group Chaining.

What this means in practice: the database will accept a connection on Port 3306 only if the requesting resource is an AWS resource that has PrestaShop-Web-SG attached to it. If an attacker reaches the VPC through some other path and does not carry that security group tag, the connection is refused at the network layer. The database has no public IP address (RDS Public Access is set to No), so it is not reachable from the internet regardless of what the inbound rules say.

This combination, no public IP plus security group chaining, means the attack surface against the database is reduced to a single vector: a compromised EC2 instance carrying the web security group. Every other attack path is closed.

---

## Security Group Chaining: How It Works

```
Internet
    |
    | Port 80 (HTTP)
    v
[ PrestaShop-Web-SG ]  <-- sg-06bfb5512c584778b
[ EC2 t3.micro      ]
    |
    | Port 3306 (MySQL)
    | Source: sg-06bfb5512c584778b
    v
[ PrestaShop-DB-SG  ]  <-- sg-0c85b5be41b4af149
[ RDS MySQL 8.4     ]  <-- No public IP. VPC-internal only.
    |
    X  (Public internet cannot reach this layer)
```

The database has no path to or from the public internet. The only entity that can open a connection to Port 3306 is an AWS resource that carries the PrestaShop-Web-SG tag. No static IPs. No CIDR ranges. No maintenance windows where an IP change breaks the rule.

---

## Reproducing This Configuration

To recreate these security groups in a new environment:

**Web SG:**
```bash
# Create the security group
aws ec2 create-security-group \
  --group-name PrestaShop-Web-SG \
  --description "Perimeter SG for PrestaShop web tier" \
  --vpc-id <your-vpc-id>

# Add HTTP rule
aws ec2 authorize-security-group-ingress \
  --group-id <web-sg-id> \
  --protocol tcp --port 80 --cidr 0.0.0.0/0

# Add SSH rule (replace with your management IP)
aws ec2 authorize-security-group-ingress \
  --group-id <web-sg-id> \
  --protocol tcp --port 22 --cidr <your-management-ip>/32
```

**DB SG:**
```bash
# Create the security group
aws ec2 create-security-group \
  --group-name PrestaShop-DB-SG \
  --description "Internal data layer SG for RDS MySQL" \
  --vpc-id <your-vpc-id>

# Add MySQL rule sourced from Web SG (chaining)
aws ec2 authorize-security-group-ingress \
  --group-id <db-sg-id> \
  --protocol tcp --port 3306 \
  --source-group <web-sg-id>
```

When attaching to RDS, set Public Access to No and select PrestaShop-DB-SG as the VPC security group. The database will have no public IP and will only accept traffic from the web tier.

---

*John Ejoke Oghenekewe | Cybersecurity Analyst | SOC Engineer | February 2026*
