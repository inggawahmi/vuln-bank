pipeline{
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
                    sh 'trufflehog filesystem . --exclude-paths trufflehog-excluded-paths --fail --json --no-update > trufflehog-scan-result.json'
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
                    withCredentials([string(credentialsId: 'DiscordWebhook', variable: 'DISCORD_WEBHOOK')]) {
                        script {
                            if (fileExists('snyk-scan-report.json')) {
                                def json = new groovy.json.JsonSlurper().parse(new File('snyk-scan-report.json'))
                                def findings = []
                                if (json.vulnerabilities) {
                                    findings = json.vulnerabilities.findAll { it.severity?.toLowerCase() == 'critical' }.collect {
                                        [title: it.title ?: it.id ?: 'unknown', severity: it.severity]
                                    }
                                }
                                if (findings) {
                                    def summary = findings.take(5).collect { "- ${it.title} (${it.severity})" }.join("\n")
                                    def payload = [
                                        username: "Jenkins Security Bot",
                                        embeds: [[
                                            title: "Snyk SCA — Critical Findings",
                                            description: "Job: `${env.JOB_NAME}`\nBuild: #${env.BUILD_NUMBER}\n\n${summary}",
                                            url: env.BUILD_URL ?: "",
                                            color: 16711680
                                        ]]
                                    ]
                                    writeFile file: "discord_snyk_sca.json", text: groovy.json.JsonOutput.toJson(payload)
                                    sh "curl -s -H 'Content-Type: application/json' -X POST -d @discord_snyk_sca.json '${DISCORD_WEBHOOK}' || true"
                                }
                            }
                        }
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
        }
    }
}