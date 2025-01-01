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

## Repository Structure

### `.github/workflows`

This directory contains GitHub Actions workflows that automate the pipeline:

1. **`main.yaml`**:
   - Main workflow file orchestrating the CI/CD process.
   - Includes steps for running Threagile, evaluating results with OPA, and archiving artifacts.

2. **`gate.yaml`**:
   - Workflow specifically designed for gating decisions based on OPA evaluations.
   - Ensures that deployments are blocked if security thresholds are not met.

3. **`score.yaml`**:
   - Focuses on scoring vulnerabilities detected in the Threagile outputs.
   - Uses OPA to compute and validate security scores.

4. **`score-testing.yaml`**:
   - Workflow designed to test the scoring mechanism and validate its reliability under various conditions.

5. **`json.yaml`**:
   - Handles JSON output processing and validation to ensure compatibility with policy evaluation.

6. **`gate-testing.yaml`**:
   - Simulates gating scenarios to verify the accuracy and robustness of policy enforcement.

### `threagile.yaml`
This file contains the threat model definition in YAML format. It specifies application details, architecture, data assets, and other parameters used by Threagile to perform threat analysis.

### `policies/vulnerabilities`
This directory contains OPA policies written in Rego language to enforce security rules. Examples include:

- Detecting high or critical vulnerabilities.
- Calculating security scores based on predefined thresholds.
- Validating the presence of essential artifacts.

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
