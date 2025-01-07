package policies.vulnerabilities

# Purpose:
# Assigns a risk score based on different levels of risks and evaluates them against a predefined threshold.
#
# Mechanism:
# - Calculates a cumulative risk score by weighing different risk levels.
# - Compares the total score against a threshold.
#
# Deny if:
# 1. The 'risks' data is missing or incomplete.
# 2. The cumulative risk score is below the predefined threshold.
# 3. There are unscored risks present in critical or high-severity categories.
#
# Focus:
# Quantitative assessment of risk levels, emphasizing score computation for decision-making.

import rego.v1

# Define the scoring weights for unchecked vulnerabilities
weights := {
	"critical": 11,
	"elevated": 7,
	"high": 5,
	"medium": 0.5,
	"low": 0,
}

# Define constants
severities := ["critical", "elevated", "high", "medium", "low"]

default total_marks := 100
default threshold := 80

default deduction_missing_stats := 0

# Input validation
valid_input if {
	is_object(input.risks)
	count(severities) == count([s | s in severities; input.risks[s].unchecked != null])
}

# Define deduction for missing stats.json
deduction_missing_stats := 31 if {
	not valid_input
}

# Calculate deductions for unchecked vulnerabilities
deduction_vulnerabilities := sum([(weights[s] * input.risks[s].unchecked) | s in severities]) if {
	valid_input
}

# Calculate total deductions with bounds checking
total_deductions := min([deduction_missing_stats + deduction_vulnerabilities, total_marks])

# Calculate total score with bounds checking
score := max([total_marks - total_deductions, 0])

# Deny rules with specific error messages
deny[msg] if {
	not valid_input
	msg := "OPA Policy Check Failed: Invalid or missing risk data. Ensure 'risks' object contains all required severity levels with valid 'unchecked' counts."
}

deny[msg] if {
	valid_input
	score < threshold
	msg := sprintf("OPA Policy Check Failed: Vulnerability score %d is below required threshold of %d. Total deductions: %d", [score, threshold, total_deductions])
}

# Pass messages with detailed information
pass[msg] if {
	valid_input
	score >= threshold
	msg := sprintf("OPA Policy Check Passed: Vulnerability score %d meets threshold of %d. Total deductions: %d", [score, threshold, total_deductions])
}

# Detailed scoring breakdown for debugging
score_details := {
	"total_marks": total_marks,
	"threshold": threshold,
	"deductions": {
		"missing_stats": deduction_missing_stats,
		"vulnerabilities": deduction_vulnerabilities,
		"total": total_deductions,
	},
	"final_score": score,
}

# Helper to determine status
status := "PASS" if {
	valid_input
	score >= threshold
}

status := "FAIL" if {
	not valid_input
	score < threshold
}
