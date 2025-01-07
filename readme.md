# Threagile CI/CD Pipeline with OPA Integration

This repository demonstrates how to integrate Threagile into a CI/CD pipeline to perform threat modeling and leverage Open Policy Agent (OPA) for making gating decisions based on security policies. Additionally, it showcases the potential of using OPA for approval automation in CI/CD workflows.

## Overview

Threagile is a lightweight threat modeling tool that generates actionable security insights from YAML-based threat model definitions. OPA is used to evaluate these outputs and enforce security policies during the CI/CD process. This integration ensures that deployments meet security requirements before proceeding.

## Key Features

- **Threagile Integration**: Automatically generates security threat models and risk assessments.
- **OPA Policy Evaluation**: Uses OPA to enforce security policies based on Threagile outputs.
- **Gating Decisions**: Blocks pipeline progression if high or critical vulnerabilities are detected.
- **Approval Automation**: Demonstrates how OPA can automate approval processes within CI/CD pipelines.
- **Comprehensive Tests**: Implements multiple scenarios to validate policy enforcement.
- **Automated Report Uploads**: Facilitates sharing of JSON results and other artifacts.

## Repository Structure

### `.github/workflows`

This directory contains GitHub Actions workflows that automate the pipeline:

1. **`advance-scoring.yaml`**:
   - Focuses on advanced scoring mechanisms.
   - Uses OPA to compute and validate detailed security scores.

2. **`gating.yaml`**:
   - Workflow specifically designed for gating decisions based on OPA evaluations.
   - Ensures that deployments are blocked if security thresholds are not met.

3. **`simple-scoring.yaml`**:
   - Implements basic scoring for vulnerabilities detected in Threagile outputs.

4. **`upload-json.yaml`**:
   - Automates the upload of JSON results from Threagile for further analysis.

5. **`upload-reports.yaml`**:
   - Handles uploading of reports and other artifacts for review.

6. **Test Workflows**:
   - **`TEST-advanced-scoring.yaml`**: Validates advanced scoring mechanisms.
   - **`TEST-gating.yaml`**: Simulates gating scenarios for testing.
   - **`TEST-simple-scoring.yaml`**: Tests the reliability of simple scoring functionality.

### `threagile.yaml`
This file contains the threat model definition in YAML format. It specifies application details, architecture, data assets, and other parameters used by Threagile to perform threat analysis.

### `policies/vulnerabilities`

This directory contains OPA policies written in Rego language to enforce security rules and evaluate risks identified by Threagile. Below are the details of each policy:

#### 1. **`gate.rego`**: Gating Decisions
- **Purpose**: Implements a gating mechanism that halts pipeline progression if high or critical vulnerabilities are detected.
- **Usage**: This policy evaluates the presence and count of unchecked vulnerabilities in the categories of `critical`, `elevated`, and `high`. If thresholds are exceeded, it blocks the deployment process.
- **Key Features**:
  - Ensures the `risks` data exists and is populated.
  - Denies progression if vulnerabilities are unresolved in critical categories.
  - Straightforward logic focusing on severity-based gating decisions.

#### 2. **`risk.rego`**: Advanced Risk Evaluation
- **Purpose**: Provides a comprehensive evaluation of risks by considering severity, impact, and likelihood.
- **Usage**: This policy calculates a cumulative risk score using weights for each factor (severity, impact, and likelihood). It denies progression if the combined risk score exceeds acceptable thresholds or if critical risks have high likelihood and impact.
- **Key Features**:
  - Assigns weights to dimensions like `exploitation likelihood` and `impact`.
  - Denies deployments based on holistic risk assessments rather than severity alone.
  - Incorporates thresholds for scoring to align with organizational standards.

#### 3. **`score.rego`**: Scoring Vulnerabilities
- **Purpose**: Assigns a numerical score based on risks and compares it against a predefined threshold.
- **Usage**: This policy calculates a cumulative score from different risk levels (e.g., critical, high, medium) using weighted scores. Deployments are blocked if the score falls below the required threshold.
- **Key Features**:
  - Evaluates `unchecked` vulnerabilities across all severity levels.
  - Provides detailed scoring breakdowns for debugging.
  - Implements clear thresholds for passing or failing deployments.

### `threagile/output`
This directory stores outputs from Threagile, such as:

- Data flow and data asset diagrams.
- JSON files summarizing threats and vulnerabilities.
- Risk assessments in various formats (PDF, JSON, Excel).

## Workflow Description

### 1. **Run Threagile Analysis**
   - Generates threat models and risk reports based on the `threagile.yaml` file.
   - Outputs include:
     - Data flow diagrams (DFD).
     - Risk assessments.
     - JSON files summarizing threats and vulnerabilities.

### 2. **Evaluate with OPA**
   - Processes the outputs of Threagile using OPA policies.
   - Validates against security rules, such as:
     - Blocking deployments with high-severity vulnerabilities.
     - Ensuring key artifacts are present.
     - Calculating and validating security scores.

### 3. **Gating and Reporting**
   - If policies are violated, the pipeline halts with detailed failure logs.
   - Artifacts such as DFDs, risk reports, and policy evaluation results are archived for review.

### 4. **Automated Report Uploads**
   - JSON results and additional reports are automatically uploaded for further analysis.

## How to Use

1. **Setup Repository**:
   - Clone the repository and navigate to the root directory.
   - Update the `threagile.yaml` file with your application's threat model.

2. **Configure GitHub Secrets** (if applicable):
   - Add necessary secrets for repository access or deployment.

3. **Run Workflows**:
   - Trigger workflows automatically on push, pull request, or manually via `workflow_dispatch`.
   - Review outputs and logs in the GitHub Actions interface.

4. **Customize Policies**:
   - Modify OPA policies in the `policies/vulnerabilities` directory to align with organizational requirements.

## Prerequisites

- **GitHub Actions** enabled in your repository.
- Basic understanding of YAML, Rego, and CI/CD pipelines.
- Threagile and OPA tools installed locally for testing (optional).

## Conclusion

This repository serves as a starting point for integrating Threagile and OPA into your CI/CD pipeline. It demonstrates how automated threat modeling, policy enforcement, and approval automation can enhance security and ensure compliance with organizational standards.
