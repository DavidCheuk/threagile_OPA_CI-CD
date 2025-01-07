package policies.vulnerabilities

import rego.v1

# Purpose: Implements a simple gating mechanism.
# Mechanism: Evaluates the number of high and critical vulnerabilities in a system.
# Decision Logic:
# If the number of high or critical vulnerabilities exceeds a certain threshold, 
# the action is deemed to fail.
# Focus: Straightforward evaluation based solely on the presence and count of critical issues.

# Deny if:
# 1. The 'risks' data is missing.
# 2. Any of the critical, elevated, or high severities have 'unchecked' vulnerabilities.

deny contains msg if {
	# Case 1: 'risks' key is missing or empty
	not input.risks
	msg := "Error: Threagile evaluation has not been performed. Missing or empty 'risks' data."
}

deny contains msg if {
	# Case 2: Critical vulnerabilities have unchecked items
	input.risks.critical.unchecked > 0
	msg := sprintf("Critical vulnerabilities unchecked: %d", [input.risks.critical.unchecked])
}

deny contains msg if {
	# Case 3: Elevated vulnerabilities have unchecked items
	input.risks.elevated.unchecked > 0
	msg := sprintf("Elevated vulnerabilities unchecked: %d", [input.risks.elevated.unchecked])
}

deny contains msg if {
	# Case 4: High vulnerabilities have unchecked items
	input.risks.high.unchecked > 0
	msg := sprintf("High vulnerabilities unchecked: %d", [input.risks.high.unchecked])
}
