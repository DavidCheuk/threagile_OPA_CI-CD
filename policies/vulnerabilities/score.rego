package policies.vulnerabilities

import rego.v1

# Define the scoring weights for unchecked vulnerabilities
weights := {
	"critical": 21,
	"elevated": 11,
	"high": 5,
	"medium": 1,
	"low": 0,
}

# Define the total marks
total_marks := 100

# Define deduction for missing stats.json
deduction_missing_stats := 31 if {
	not input.risks
}

deduction_missing_stats := 0 if {
	input.risks
}

# Calculate deductions for unchecked vulnerabilities
deduction_vulnerabilities := sum([
	weights.critical * input.risks.critical.unchecked,
	weights.elevated * input.risks.elevated.unchecked,
	weights.high * input.risks.high.unchecked,
	weights.medium * input.risks.medium.unchecked,
	weights.low * input.risks.low.unchecked,
])

# Calculate total deductions
total_deductions := deduction_missing_stats + deduction_vulnerabilities

# Calculate total score
score := total_marks - total_deductions

# Define threshold
threshold := 80

# Deny if score is below threshold
deny contains msg if {
	score < threshold
	msg := sprintf("OPA Policy Check Failed: Total vulnerability score %d is below threshold of %d.", [score, threshold])
}

# Optional: Pass message for logging purposes
pass contains msg if {
	score >= threshold
	msg := sprintf("OPA Policy Check Passed: Total vulnerability score %d meets the threshold of %d.", [score, threshold])
}
