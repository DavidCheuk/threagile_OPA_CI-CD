package threagile.vulnerabilities

# Deny if:
# 1. The 'risks' data is missing.
# 2. Any of the critical, elevated, or high severities have 'unchecked' vulnerabilities.

deny[msg] {
    # Case 1: 'risks' key is missing or empty
    not data.risks
    msg := "Error: Threagile evaluation has not been performed. Missing or empty 'risks' data."
}

deny[msg] {
    # Case 2: Critical vulnerabilities have unchecked items
    data.risks.critical.unchecked > 0
    msg := sprintf("Critical vulnerabilities unchecked: %d", [data.risks.critical.unchecked])
}

deny[msg] {
    # Case 3: Elevated vulnerabilities have unchecked items
    data.risks.elevated.unchecked > 0
    msg := sprintf("Elevated vulnerabilities unchecked: %d", [data.risks.elevated.unchecked])
}

deny[msg] {
    # Case 4: High vulnerabilities have unchecked items
    data.risks.high.unchecked > 0
    msg := sprintf("High vulnerabilities unchecked: %d", [data.risks.high.unchecked])
}
