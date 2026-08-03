# CI Integration Examples

## GitHub Actions

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # for SARIF upload
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history for `history` command

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install secret-scanner
        run: pip install secret-scanner

      - name: Scan working tree
        run: secret-scanner scan . --fail-on high --format sarif --output scan.sarif

      - name: Scan git history (optional, slower)
        run: secret-scanner history . --fail-on high --format sarif --output history.sarif || true

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan.sarif

      - name: Upload HTML report as artifact
        if: always()
        run: secret-scanner scan . --format html --output report.html || true

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: secret-scan-report
          path: report.html
```

## GitLab CI

```yaml
# .gitlab-ci.yml
secret-scan:
  image: python:3.12
  stage: test
  script:
    - pip install secret-scanner
    - secret-scanner scan . --fail-on high --format json --output scan.json
  artifacts:
    when: always
    paths:
      - scan.json
    reports:
      secret_detection: scan.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"
```

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        name: Secret scan
        image: python:3.12
        script:
          - pip install secret-scanner
          - secret-scanner scan . --fail-on high
```

## Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Secret Scan') {
            steps {
                sh 'pip install secret-scanner'
                sh 'secret-scanner scan . --fail-on high --format json --output scan.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'scan.json', fingerprint: true
                }
            }
        }
    }
}
```

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1
jobs:
  secret-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run: pip install secret-scanner
      - run: secret-scanner scan . --fail-on high
workflows:
  version: 2
  scan:
    jobs:
      - secret-scan
```

## Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include: ['*']
pool:
  vmImage: 'ubuntu-latest'
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
  - script: pip install secret-scanner
    displayName: Install secret-scanner
  - script: secret-scanner scan . --fail-on high --format sarif --output scan.sarif
    displayName: Scan
    continueOnError: true
  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: 'scan.sarif'
      artifactName: 'SARIF'
```

## Travis CI

```yaml
# .travis.yml
language: python
python:
  - "3.12"
install:
  - pip install secret-scanner
script:
  - secret-scanner scan . --fail-on high
```

## Pre-commit Hook

Install a pre-commit hook that runs the scanner before each commit:

```bash
secret-scanner install-hooks .
# or for pre-push:
secret-scanner install-hooks . --hook pre-push
```

This creates `.git/hooks/pre-commit` (or `pre-push`) that runs:

```bash
secret-scanner scan . --fail-on high --quiet
```

Adjust the severity threshold by editing the hook file.

## Baseline Mode for Existing Projects

For projects with pre-existing secrets in the repo that can't be removed
immediately, use baseline mode to suppress known findings:

```bash
# First time: save the current findings as the baseline
secret-scanner baseline .

# Commit the baseline file (it's stored in ~/.cache/secret-scanner/history.db)
# In CI, run with --baseline to only fail on NEW secrets:
secret-scanner scan . --baseline --fail-on high
```

## SARIF Integration

SARIF is the industry-standard format for static analysis results. It's
supported by GitHub Code Scanning, Azure DevOps, Visual Studio Code, and
many other tools.

```bash
secret-scanner scan . --format sarif --output scan.sarif
```

Upload to GitHub:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif
```

The SARIF output includes:
- Rule metadata (id, name, description, severity)
- Location (file, line, column)
- Confidence score
- Recommendation
- Partial fingerprint (for deduplication across scans)
