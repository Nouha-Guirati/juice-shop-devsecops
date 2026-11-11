
pipeline {
    agent any

    options {
        disableConcurrentBuilds()
    }

    environment {
        BASELINE_DIR = '/var/jenkins_home/devsecops-baselines/juice-shop'
    }

    stages {

        // 1. CHECKOUT
        stage('Checkout') {
            steps {
                echo 'Preparation du code source Juice Shop'

                deleteDir()

                // Recuperer le code depuis le SCM configure dans Jenkins
                checkout scm

                sh '''
                    set -eu

                    echo "Verification du code source..."

                    test -f package.json || {
                        echo "ERREUR : package.json absent."
                        exit 1
                    }

                    test -d .git || {
                        echo "ERREUR : depot Git absent. Semgrep a besoin de l'historique Git."
                        exit 1
                    }

                    test -s .gitleaks-baseline.json || {
                        echo "ERREUR : baseline Gitleaks absente."
                        exit 1
                    }

                    test -s reports/trivy-baseline.json || {
                        echo "ERREUR : baseline Trivy SCA absente."
                        exit 1
                    }

                    mkdir -p reports "$BASELINE_DIR"

                    git fetch origin main

                    git rev-parse --verify origin/main >/dev/null

                    echo "Branche actuelle :"
                    git branch --show-current || true

                    echo "Commit analyse :"
                    git rev-parse --short HEAD

                    echo "Code source prepare."
                '''

                // Script commun pour comparer les rapports Trivy
                sh '''
                    cat > /tmp/compare_trivy.py <<'PY'
import json
import os
import shutil
import sys

baseline_path = sys.argv[1]
current_path = sys.argv[2]
scan_type = sys.argv[3]

def load_findings(path):
    with open(path, encoding="utf-8") as f:
        report = json.load(f)

    findings = {}

    for result in report.get("Results") or []:
        target = result.get("Target", "")

        if scan_type in ("sca", "image"):
            for item in result.get("Vulnerabilities") or []:
                severity = (item.get("Severity") or "").upper()

                if severity not in ("HIGH", "CRITICAL"):
                    continue

                key = (
                    target,
                    item.get("VulnerabilityID", ""),
                    item.get("PkgName", ""),
                    item.get("InstalledVersion", ""),
                    severity
                )

                findings[key] = item.get("FixedVersion", "")

        elif scan_type == "iac":
            for item in result.get("Misconfigurations") or []:
                severity = (item.get("Severity") or "").upper()

                if severity not in ("HIGH", "CRITICAL"):
                    continue

                cause = item.get("CauseMetadata") or {}

                key = (
                    target,
                    item.get("ID", ""),
                    item.get("AVDID", ""),
                    cause.get("Resource", ""),
                    severity,
                    item.get("Title", "")
                )

                findings[key] = item.get("Message", "")

    return findings

try:
    current = load_findings(current_path)

    if not os.path.isfile(baseline_path):
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
        shutil.copy2(current_path, baseline_path)

        print("BASELINE INITIALE : " + scan_type)
        print("Constats historiques enregistres :", len(current))
        print("Les prochains scans compareront les nouveaux constats a cette baseline.")

        sys.exit(0)

    baseline = load_findings(baseline_path)

except (OSError, json.JSONDecodeError, TypeError, IndexError) as error:
    print("ERREUR COMPARAISON TRIVY :", error)
    sys.exit(1)

new_findings = {
    key: value for key, value in current.items()
    if key not in baseline
}

print("Constats baseline :", len(baseline))
print("Constats actuels :", len(current))
print("Nouveaux constats :", len(new_findings))

if new_findings:
    for key, value in new_findings.items():
        print("NOUVEAU :", key, value)

    print("SECURITY GATE : ECHEC")
    sys.exit(1)

print("SECURITY GATE : VALIDEE")
PY
                '''
            }
        }

        // 2. SECRETS SCAN - GITLEAKS
        stage('Secrets Scan') {
            steps {
                echo 'Detection des nouveaux secrets avec Gitleaks'

                sh '''
                    set -eu

                    BASELINE=".gitleaks-baseline.json"

                    TMP_BASELINE="$(mktemp /tmp/gitleaks-baseline.XXXXXX.json)"

                    cp "$BASELINE" "$TMP_BASELINE"

                    restore_baseline() {
                        cp "$TMP_BASELINE" "$BASELINE"
                        rm -f "$TMP_BASELINE"
                    }

                    trap restore_baseline EXIT

                    // Ne pas scanner le fichier de baseline lui-meme.
                    rm "$BASELINE"

                    gitleaks dir \
                        --verbose \
                        --baseline-path "$TMP_BASELINE" \
                        .
                '''
            }
        }

        // 3. SAST - SONARQUBE + SEMGREP
        stage('SAST Sonar & Semgrep') {
            steps {
                echo 'Analyse statique du code'

                script {
                    def scannerHome = tool 'SonarScanner'

                    withSonarQubeEnv('sonarqube') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner \
                                -Dsonar.projectKey=juice-shop \
                                -Dsonar.projectName=Juice-Shop \
                                -Dsonar.sources=. \
                                -Dsonar.exclusions='**/node_modules/**,**/coverage/**,**/dist/**,**/build/**,**/reports/**,**/.gitleaks-baseline.json'
                        """
                    }
                }

                // Semgrep compare le code actuel avec origin/main.
                sh '''
                    set -eu

                    docker run --rm \
                        --volumes-from jenkins \
                        -w "$WORKSPACE" \
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

        // 5. INFRASTRUCTURE AS CODE - TRIVY
        stage('IaC Scan - Trivy') {
            steps {
                echo 'Analyse des configurations Terraform'

                sh '''
                    set -eu

                    trivy config . \
                        --severity HIGH,CRITICAL \
                        --format json \
                        --output reports/trivy-iac.json

                    test -s reports/trivy-iac.json

                    python3 /tmp/compare_trivy.py \
                        "$BASELINE_DIR/trivy-iac-baseline.json" \
                        reports/trivy-iac.json \
                        iac
                '''
            }
        }

        // 6. BUILD & TESTS
        stage('Build & Tests') {
            steps {
                echo 'Installation des dependances et execution des tests'

                sh '''
                    set -eu

                    docker run --rm \
                        --volumes-from jenkins \
                        -w "$WORKSPACE" \
                        node:24 \
                        sh -c '
                            if [ -f package-lock.json ]; then
                                npm ci
                            else
                                npm install
                            fi

                            npm run test:server
                        '
                '''
            }
        }

        // 7. SCA - DEPENDENCIES SCAN
        stage('SCA - Trivy') {
            steps {
                echo 'Analyse des dependances et bibliotheques'

                sh '''
                    set -eu

                    trivy fs . \
                        --scanners vuln \
                        --severity HIGH,CRITICAL \
                        --ignore-unfixed \
                        --format json \
                        --output reports/trivy-sca.json

                    test -s reports/trivy-sca.json

                    python3 /tmp/compare_trivy.py \
                        reports/trivy-baseline.json \
                        reports/trivy-sca.json \
                        sca
                '''
            }
        }

        // 8. DOCKER BUILD
        stage('Docker Build') {
            steps {
                echo 'Construction de l image Docker Juice Shop'

                sh '''
                    set -eu

                    docker build \
                        -t juice-shop:${BUILD_NUMBER} \
                        .
                '''
            }
        }

        // 9. DOCKER IMAGE SCAN
        stage('Image Scan - Trivy') {
            steps {
                echo 'Analyse de l image Docker'

                sh '''
                    set -eu

                    trivy image \
                        --scanners vuln \
                        --severity HIGH,CRITICAL \
                        --ignore-unfixed \
                        --format json \
                        --output reports/trivy-image.json \
                        juice-shop:${BUILD_NUMBER}

                    test -s reports/trivy-image.json

                    python3 /tmp/compare_trivy.py \
                        "$BASELINE_DIR/trivy-image-baseline.json" \
                        reports/trivy-image.json \
                        image
                '''
            }
        }

        // 10. DEPLOYMENT STAGING
        stage('Deploy - Staging') {
            steps {
                echo 'Deploiement de Juice Shop dans Docker'

                sh '''
                    set -eu

                    docker network inspect devsecops >/dev/null 2>&1 || \
                        docker network create devsecops

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

                    echo "Juice Shop accessible sur le port 3001."
                '''
            }
        }

        // 11. DAST - RESERVE
        stage('DAST - A integrer') {
            steps {
                echo 'DAST non execute.'
                echo 'Etape reservee pour integration OWASP ZAP.'
            }
        }

        // 12. FINALISATION
        stage('Finalisation') {
            steps {
                echo 'Finalisation du pipeline DevSecOps'

                sh '''
                    echo "BUILD : ${BUILD_NUMBER}"

                    echo "Rapports generes :"

                    ls -lh reports/ || true
                '''
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
            archiveArtifacts(
                artifacts: 'reports/**/*',
                allowEmptyArchive: true
            )

            echo 'Fin du pipeline.'
        }
    }
}
