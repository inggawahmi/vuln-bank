// === Fungsi global buat notifikasi Discord ===
def notifyDiscordIfHighOrCritical(reportFile, toolName) {
    if (!fileExists(reportFile)) {
        echo "[NOTIFY] ${toolName}: report ${reportFile} not found"
        return
    }

    def findings = []

    if (reportFile.endsWith(".json")) {
        def report = readJSON file: reportFile

        if (toolName == "Snyk SCA") {
            findings = report.vulnerabilities?.findAll { v ->
                v.severity?.toLowerCase() in ["critical", "high"]
            }?.collect { v ->
                [title: v.title ?: v.id ?: "unknown", severity: v.severity]
            }
        }

        if (toolName == "Snyk SAST") {
            findings = report.issues?.findAll { i ->
                i.severity?.toLowerCase() in ["critical", "high"]
            }?.collect { i ->
                [title: i.message ?: i.id ?: "unknown", severity: i.severity]
            }
        }

        if (toolName == "Trivy") {
            findings = []
            report.Results?.each { result ->
                result.Misconfigurations?.each { m ->
                    if (m.Severity?.toLowerCase() in ["critical","high"]) {
                        findings << [title: m.Title ?: m.ID ?: "unknown", severity: m.Severity]
                    }
                }
            }
        }
    }

    if (reportFile.endsWith(".xml") && toolName == "OWASP ZAP") {
        def zapReport = readFile file: reportFile
        // Simple parse: cari <alertitem> dan riskdesc
        def matcher = zapReport =~ /(?s)<alertitem>.*?<alert>(.*?)<\/alert>.*?<riskdesc>(.*?)<\/riskdesc>/
    while (matcher.find()) {
        def title = matcher.group(1)?.trim()
        def risk = matcher.group(2)?.toLowerCase()
        if (risk?.contains("high") || risk?.contains("critical")) {
            findings << [title: title, severity: matcher.group(2)]
        }
    }
}

    if (findings && findings.size() > 0) {
        def summary = findings.take(5).collect { "- ${it.title} (${it.severity})" }.join("\n")
        def payload = [
            username: "Jenkins Security Bot",
            embeds: [[
                title: "${toolName} — High/Critical Findings",
                description: "Job: `${env.JOB_NAME}`\nBuild: #${env.BUILD_NUMBER}\n\n${summary}",
                url: env.BUILD_URL ?: "",
                color: 16711680
            ]]
        ]
        withCredentials([string(credentialsId: 'DiscordWebhook', variable: 'DISCORD_WEBHOOK')]) {
            writeFile file: "discord_${toolName.replaceAll('[^A-Za-z0-9]', '_')}.json", text: groovy.json.JsonOutput.toJson(payload)
            sh "curl -s -H 'Content-Type: application/json' -X POST -d @discord_${toolName.replaceAll('[^A-Za-z0-9]', '_')}.json $DISCORD_WEBHOOK || true"
        }
        echo "[NOTIFY] ${toolName}: sent ${findings.size()} findings to Discord"
    } else {
        echo "[NOTIFY] ${toolName}: no high/critical findings"
    }
}


pipeline {
    agent any
    environment {
        DOCKERHUB_CREDENTIALS = credentials('DockerLogin')
        SNYK_CREDENTIALS = credentials('SnykToken')
        SONARQUBE_CREDENTIALS = credentials('SonarToken')
    }
    stages {

        stage ('Secret Scanning using Trufflehog'){
            agent {
                docker {
                    image 'trufflesecurity/trufflehog:latest'
                    args '--entrypoint='
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'trufflehog filesystem . --exclude-paths trufflehog-excluded-paths.txt --fail --json --no-update > trufflehog-scan-result.json'
                }
                sh 'cat trufflehog-scan-result.json'
                archiveArtifacts artifacts: 'trufflehog-scan-result.json'
            }
        }

        stage('Checkout Source dari Github') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                sh 'docker-compose build'
            }
        }

        stage('SCA Scan with Snyk') {
            agent {
                docker {
                    image 'inggawahmi/snyk-python:3.9'
                    args '--user root -v /var/run/docker.sock:/var/run/docker.sock --entrypoint='
                }
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'SnykToken', usernameVariable: 'USER', passwordVariable: 'SNYK_TOKEN')]) {
                    sh '''
                        snyk auth $SNYK_TOKEN
                        snyk test --file=requirements.txt --json > snyk-scan-report.json || EXIT_CODE=$?
                        echo "Snyk finished with exit code $EXIT_CODE"
                        exit 0
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'snyk-scan-report.json'
                    script {
                        notifyDiscordIfHighOrCritical('snyk-scan-report.json', 'Snyk SCA')
                    }
                }
            }
        }
        
        stage('SCA Trivy scan Dockerfile Misconfiguration') {
            agent {
                docker {
                    image 'aquasec/trivy:latest'
                    args '-u root --network host --entrypoint='
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'mkdir -p .json && trivy config Dockerfile --exit-code=1 --format json > .json/trivy-scan-dockerfile-report.json'
                }
                sh 'cat .json/trivy-scan-dockerfile-report.json'
                archiveArtifacts artifacts: '.json/trivy-scan-dockerfile-report.json'
            }
            post {
                always {
                    script {
                        notifyDiscordIfHighOrCritical('.json/trivy-scan-dockerfile-report.json', 'Trivy')
                    }
                }
            }
        }

        stage('SAST Scan with Snyk') {
            agent {
                docker {
                    image 'snyk/snyk:python'
                    args '--user root --network host --entrypoint='
                }
            }
            environment {
                SNYK_CREDS = credentials('SnykToken')
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                        snyk auth "$SNYK_CREDS_PSW"
                        snyk code test --json > snyk-scan-code-report.json
                    '''
                }
                sh 'cat snyk-scan-code-report.json'
                archiveArtifacts artifacts: 'snyk-scan-code-report.json'
            }
            post {
                always {
                    script {
                        notifyDiscordIfHighOrCritical('snyk-scan-code-report.json', 'Snyk SAST')
                    }
                }
            }
        }

        stage('Build Docker Image and Push to Docker Registry') {
            agent {
                docker {
                    image 'docker:dind'
                    args '--user root -v /var/run/docker.sock:/var/run/docker.sock'
                }
            }
            steps {
                sh 'docker build -t inggawahmi/vuln-bank:0.1 .'
                sh 'echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin'
                sh 'docker push inggawahmi/vuln-bank:0.1'
            }
        }

        stage('Deploy Docker Image') {
            agent {
                docker {
                    image 'kroniak/ssh-client'
                    args '--user root -v /var/run/docker.sock:/var/run/docker.sock'
                }
            }
            steps {
                withCredentials([
                    sshUserPrivateKey(credentialsId: "DeploymentSSHKey", keyFileVariable: 'keyfile'),
                    usernamePassword(credentialsId: "DockerLogin", usernameVariable: 'tmpUser', passwordVariable: 'tmpPass')
                ]) {
                    // 1. Login ke Docker Hub
                    sh '''
                        ssh -i ${keyfile} -o StrictHostKeyChecking=no deploymentserver@192.168.1.11 \
                        "echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin"
                    '''
                    // 2. Pull image terbaru dari Docker Hub
                    sh '''
                        ssh -i ${keyfile} -o StrictHostKeyChecking=no deploymentserver@192.168.1.11 \
                        "docker pull inggawahmi/vuln-bank:0.1"
                    '''
                    // 3. Jalankan dengan docker-compose
                    sh '''
                        ssh -i ${keyfile} -o StrictHostKeyChecking=no deploymentserver@192.168.1.11 \
                        "docker compose -f /home/deploymentserver/vuln-bank/docker-compose.yml up -d"
                    '''
                }
            }
        }

        stage('DAST scan with OWASP ZAP') {
            agent {
                docker {
                    image 'ghcr.io/zaproxy/zaproxy:stable'
                    args '-u root --network host -v /var/run/docker.sock:/var/run.docker.sock --entrypoint= -v ${WORKSPACE}:/zap/wrk/:rw'
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'zap-baseline.py -t http://192.168.1.11:5000 -r zapbaseline.html -x zap_report.xml'
                }
                sh 'cp /zap/wrk/zapbaseline.html ./zapbaseline.html'
                sh 'cp /zap/wrk/zap_report.xml ./zap_report.xml'
                archiveArtifacts artifacts: 'zapbaseline.html'
                archiveArtifacts artifacts: 'zap_report.xml'
            }
            post {
                always {
                    script {
                        notifyDiscordIfHighOrCritical('zap_report.xml', 'OWASP ZAP')
                    }
                }
            }
        }
    }
}
