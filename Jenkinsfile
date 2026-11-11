pipeline {
    agent any

    stages {

        // 1. CHECKOUT
        stage('Checkout') {
            steps {
                echo 'Recuperation du code depuis GitHub'

                checkout scm

                sh '''
                    mkdir -p reports
                '''
            }
        }

        // 2. SECRETS SCAN
        stage('Secrets Scan') {
            steps {
                echo 'Detection des secrets avec Gitleaks'

                sh '''
                    gitleaks dir \
                        --verbose \
                        --baseline-path .gitleaks-baseline.json \
                        .
                '''
            }
        }

        // 3. SAST : SONARQUBE + SEMGREP
        stage('SAST Sonar & Semgrep') {
            steps {
                echo 'Analyse statique avec SonarQube et Semgrep'

                script {
                    def scannerHome = tool 'SonarScanner'

                    withSonarQubeEnv('sonarqube') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner \
                                -Dsonar.projectKey=juice-shop \
                                -Dsonar.projectName=Juice-Shop \
                                -Dsonar.sources=. \
                                -Dsonar.exclusions=**/node_modules/**,**/coverage/**,**/dist/**,**/build/**,**/reports/**
                        """
                    }
                }

                sh '''
                    git rev-parse --verify origin/main

                    docker run --rm \
                        -v "/srv/jenkins${WORKSPACE#/var/jenkins_home}:/src" \
                        -w /src \
                        semgrep/semgrep \
                        semgrep scan \
                            --config p/javascript \
                            --config p/owasp-top-ten \
                            --baseline-commit origin/main \
                            --sarif \
                            --output reports/semgrep.sarif \
                            --error \
                            --metrics=off
                '''
            }
        }

        // 4. QUALITY GATE SONARQUBE
        stage('Quality Gate') {
            steps {
                echo 'Verification du Quality Gate SonarQube'

                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        // 5. SCAN INFRASTRUCTURE AS CODE
        stage('IaC Scan - Trivy') {
            steps {
                echo 'Analyse Terraform et Infrastructure avec Trivy'

                sh '''
                    mkdir -p reports

                    trivy config . \
                        --severity HIGH,CRITICAL \
                        --format json \
                        --output reports/trivy-iac.json

                    test -s reports/trivy-iac.json
                '''
            }
        }

        // 6. BUILD & TESTS
        stage('Build & Tests') {
            steps {
                echo 'Installation des dependances et execution des tests'

                sh '''
                    docker run --rm \
                        --volumes-from jenkins \
                        -w "$WORKSPACE" \
                        node:24 \
                        sh -c "npm install && npm run test:server"
                '''
            }
        }

        // 7. SCA : DEPENDENCIES SCAN
        stage('SCA - Trivy') {
            steps {
                echo 'Analyse des dependances avec Trivy'

                sh '''
                    mkdir -p reports

                    if [ ! -s reports/trivy-baseline.json ]; then
                        echo "ERREUR : baseline Trivy absente"
                        exit 1
                    fi

                    trivy fs . \
                        --scanners vuln \
                        --severity HIGH,CRITICAL \
                        --ignore-unfixed \
                        --format json \
                        --output reports/trivy-sca.json

                    test -s reports/trivy-sca.json

                    python3 - <<'PY'
import json
import sys

def load_vulnerabilities(path):
    with open(path, encoding="utf-8") as f:
        report = json.load(f)

    findings = {}

    for result in report.get("Results") or []:
        target = result.get("Target", "")

        for vuln in result.get("Vulnerabilities") or []:
            severity = vuln.get("Severity", "").upper()

            if severity not in ("HIGH", "CRITICAL"):
                continue

            key = (
                target,
                vuln.get("VulnerabilityID", ""),
                vuln.get("PkgName", ""),
                vuln.get("InstalledVersion", ""),
                severity
            )

            findings[key] = vuln.get("FixedVersion", "")

    return findings

try:
    baseline = load_vulnerabilities("reports/trivy-baseline.json")
    current = load_vulnerabilities("reports/trivy-sca.json")
except (OSError, json.JSONDecodeError, TypeError) as error:
    print("ERREUR :", error)
    sys.exit(1)

new_findings = {
    key: value for key, value in current.items()
    if key not in baseline
}

print("Vulnerabilites baseline :", len(baseline))
print("Vulnerabilites actuelles :", len(current))
print("Nouvelles vulnerabilites :", len(new_findings))

if new_findings:
    for key, fixed in new_findings.items():
        target, cve, package, version, severity = key
        print(severity, cve, package, version, fixed, target)

    print("SECURITY GATE : ECHEC")
    sys.exit(1)

print("SECURITY GATE : VALIDEE")
PY
                '''
            }
        }

        // 8. DOCKER BUILD
        stage('Docker Build') {
            steps {
                echo 'Construction de l image Docker Juice Shop'

                sh '''
                    docker build -t juice-shop:${BUILD_NUMBER} .
                '''
            }
        }

        // 9. DOCKER IMAGE SCAN
        stage('Image Scan - Trivy') {
            steps {
                echo 'Analyse de l image Docker avec Trivy'

                sh '''
                    mkdir -p reports

                    trivy image \
                        --scanners vuln \
                        --severity HIGH,CRITICAL \
                        --ignore-unfixed \
                        --exit-code 0 \
                        --format json \
                        --output reports/trivy-image.json \
                        juice-shop:${BUILD_NUMBER}

                    test -s reports/trivy-image.json
                '''
            }
        }

        // 10. DEPLOYMENT
        stage('Deploy - Staging') {
            steps {
                echo 'Deploiement de Juice Shop dans Docker'

                sh '''
                    docker rm -f juice-shop-staging || true

                    docker run -d \
                        --name juice-shop-staging \
                        --network devsecops \
                        -p 3001:3000 \
                        juice-shop:${BUILD_NUMBER}

                    ready=0

                    for i in $(seq 1 30); do
                        if docker run --rm \
                            --network devsecops \
                            node:24 \
                            node -e "fetch('http://juice-shop-staging:3000').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
                        then
                            ready=1
                            break
                        fi

                        sleep 5
                    done

                    if [ "$ready" -ne 1 ]; then
                        echo "ERREUR : Juice Shop ne repond pas."
                        docker logs juice-shop-staging
                        exit 1
                    fi

                    echo "Juice Shop accessible sur le port 3001 de l'hote."
                '''
            }
        }

        // 11. DAST - RESERVED
        stage('DAST - A integrer') {
            steps {
                echo 'DAST non execute : aucun outil DAST confirme.'
                echo 'Etape reservee pour une future integration.'
            }
        }

        // 12. FINALISATION ET ARCHIVAGE
        stage('Post Actions') {
            steps {
                echo 'Finalisation du pipeline DevSecOps'

                sh '''
                    echo "BUILD : ${BUILD_NUMBER}"
                    echo "Rapports generes :"
                    ls -lh reports/ || true
                '''

                archiveArtifacts(
                    artifacts: 'reports/**/*',
                    allowEmptyArchive: true
                )
            }
        }
    }

    post {
        success {
            echo 'PIPELINE DEVSECOPS : SUCCESS'
        }

        failure {
            echo 'PIPELINE DEVSECOPS : FAILURE'
        }

        always {
            echo 'Fin du pipeline.'
        }
    }
}
