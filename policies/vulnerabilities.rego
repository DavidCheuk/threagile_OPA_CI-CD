package threagile.vulnerabilities

# Deny if:
# 1. Vulnerabilities data is missing.
# 2. Any vulnerability has High, Elevated, or Critical severity.
deny[msg] {
    # Case 1: Vulnerabilities data is missing or empty
    not data.vulnerabilities
    msg := "Error: Threagile evaluation has not been performed. Missing or empty 'vulnerabilities' data."
}

deny[msg] {
    # Case 2: Vulnerabilities data exists
    vuln := data.vulnerabilities[_]
    vuln.severity == "High" or vuln.severity == "Elevated" or vuln.severity == "Critical"
    msg := sprintf("Vulnerability '%s' has severity '%s'", [vuln.id, vuln.severity])
}