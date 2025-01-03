package policies.vulnerabilities

import rego.v1

# Define the scoring weights for exploitation_likelihood
exploitation_likelihood_weights := {
	"unlikely": 0.5,
	"likely": 1,
	"very-likely": 1.5,
	"frequent": 2,
}

# Define the scoring weights for exploitation_impact
exploitation_impact_weights := {
	"low": 0.5,
	"medium": 1,
	"high": 1.5,
	"very-high": 2,
}

# Define the scoring weights for Severity
severity_weights := {
	"low": 0,
	"medium": 1,
	"high": 3,
	"elevated": 4,
	"critical": 5,
}

valid_input if {
    is_array(input)
    count(input) > 0
}

# Define the total marks available
total_marks := 100

# Define deduction for missing risk.json
deduction_missing_risk := 20 if { # Arbitrary deduction value; adjust as needed
	not valid_input
}

deduction_missing_risk := 0 if {
	valid_input
}

deduction_risks := sum([
((exploitation_likelihood_weights[input[i].exploitation_likelihood] * exploitation_impact_weights[input[i].exploitation_impact]) * severity_weights[input[i].severity]) |
	some i
])

# Calculate total deductions
total_deductions := deduction_missing_risk + deduction_risks

# Calculate the final score
score := total_marks - total_deductions

# Define the threshold for passing
threshold := 80

# Deny the workflow if the score is below the threshold
deny_low_score[msg] if {
	valid_input
	score < threshold
	msg := sprintf("OPA Policy Check Failed: Total vulnerability score %d is below threshold of %d.", [score_output, threshold])
}

# Deny the workflow if risk.json is missing
deny_missing_risks[msg] if {
	not valid_input
	msg := "OPA Policy Check Failed: Threagile evaluation has not been performed. Missing or empty 'risks_identified' data."
}

# Optional: Pass message for logging purposes if the score meets/exceeds the threshold
pass[msg] if {
	input.risks_identified
	score >= threshold
	msg := sprintf("OPA Policy Check Passed: Total vulnerability score %d meets the threshold of %d.", [score, threshold])
}

# Define a rule to output the score for external access
score_output := max([score, 0])
