pipeline{
    agent any
    environment {
        DOCKERHUB_CREDENTIALS = credentials('DockerLogin')
        SNYK_CREDENTIALS = credentials('SnykToken')
    }
    stages {
        // stage ('Secret Scanning using Trufflehog'){
        //     agent {
        //         docker {
        //             image 'trufflesecurity/trufflehog:latest'
        //             args '--entrypoint='
        //         }
        //     }
        //     steps {
        //         catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
        //             sh 'trufflehog filesystem . --exclude-paths trufflehog-excluded-paths --fail --json --no-update > trufflehog-scan-result.json'
        //         }
        //         sh 'cat trufflehog-scan-result.json'
        //         archiveArtifacts artifacts: 'trufflehog-scan-result.json'
        //     }
        // }
        stage('Checkout Source dari Github') {
            steps {
                checkout scm
            }
        }
        stage('Build') {
            steps {
                sh 'docker compose build'
            }
        }
        // stage('SCA Snyk Test'){
        //     agent {
        //         docker {
        //             image 'snyk/snyk:node'
        //             args '-u root --network host --env SNYK_TOKEN=$SNYK_CREDENTIALS_PSW --entrypoint='
        //         }
        //     }
        //     steps {
        //         catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
        //             sh 'snyk test --json > snyk-scan-report.json'
        //         }
        //         sh 'cat snyk-scan-report.json'
        //         archiveArtifacts artifacts: 'snyk-scan-report.json'
        //     }
        // }
        // stage('SCA OWASP Dependency Check'){
        //     agent {
        //         docker {
        //             image 'owasp/dependency-check:latest'
        //             args '-u root -v /var/run/docker.sock:/var/run/docker.sock --entrypoint='
        //         }
        //     }
        //     steps {
        //         catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
        //             sh '/usr/share/dependency-check/bin/dependency-check.sh --scan . --project "NodeJS Goof" --format ALL --noupdate'
        //         }
        //         archiveArtifacts artifacts: 'dependency-check-report.html'
        //         archiveArtifacts artifacts: 'dependency-check-report.json'
        //         archiveArtifacts artifacts: 'dependency-check-report.xml'
        //     }
        // }
        // stage('SCA Trivy scan Dockerfile Misconfiguration') {
        //     agent {
        //         docker {
        //             image 'aquasec/trivy:latest'
        //             args '-u root --network host --entrypoint='
        //         }
        //     }
        //     steps {
        //         catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
        //             sh 'trivy config Dockerfile --exit-code=1 --format json > trivy-scan-dockerfile-report.json'
        //         }
        //         sh 'cat trivy-scan-dockerfile-report.json'
        //         archiveArtifacts artifacts: 'trivy-scan-dockerfile-report.json'
        //     }
        // }
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
                    usernamePassword(credentialsId: "DOCKERHUB_CREDENTIALS", usernameVariable: 'tmpUser', passwordVariable: 'tmpPass')
                ]) {
                    // Di sini Jenkins otomatis nyiapin env var default:
                    //   DOCKERHUB_CREDENTIALS_USR → username Docker Hub
                    //   DOCKERHUB_CREDENTIALS_PSW → password Docker Hub

                    // 1. Login Docker Hub di remote server
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
    }
}