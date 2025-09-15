pipeline{
    agent any
    environment {
        DOCKERHUB_CREDENTIALS = credentials('DockerLogin')
        SNYK_CREDENTIALS = credentials('SnykToken')
        SONARQUBE_CREDENTIALS = credentials('SonarToken')
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
        //             sh 'trufflehog filesystem . --exclude-paths trufflehog-excluded-paths.txt --fail --json --no-update > trufflehog-scan-result.json'
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
                sh 'docker-compose build'
            }
        }

        // stage('SCA Scan with Snyk') {
        //     agent {
        //         docker {
        //             image 'inggawahmi/snyk-python:3.9'
        //             args '--user root -v /var/run/docker.sock:/var/run/docker.sock --entrypoint='
        //         }
        //     }
        //     steps {
        //         withCredentials([usernamePassword(credentialsId: 'SnykToken', usernameVariable: 'USER', passwordVariable: 'SNYK_TOKEN')]) {
        //             sh '''
        //                 snyk auth $SNYK_TOKEN
        //                 snyk test --file=requirements.txt --json > snyk-scan-report.json || EXIT_CODE=$?
        //                 echo "Snyk finished with exit code $EXIT_CODE"
        //                 exit 0

        //             '''
        //         }
        //     }
        //     post {
        //         always {
        //             archiveArtifacts artifacts: 'snyk-scan-report.json'
        //         }
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
        //             sh '/usr/share/dependency-check/bin/dependency-check.sh --scan . --project "Vuln-bank" --format ALL --noupdate'
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
        //             sh 'mkdir -p .json && trivy config Dockerfile --exit-code=1 --format json > .json/trivy-scan-dockerfile-report.json'
        //         }
        //         sh 'cat .json/trivy-scan-dockerfile-report.json'
        //         archiveArtifacts artifacts: '.json/trivy-scan-dockerfile-report.json'
        //     }
        // }

        stage('SAST Scan with SonarQube') {
            agent {
                docker {
                    image 'sonarsource/sonar-scanner-cli:latest'
                    args '--network host -v ".:/usr/src" --entrypoint='
                }
            }
            steps {
                // Ambil token Sonar dari credentials (harapkan berupa secret text)
                withCredentials([usernamePassword(credentialsId: 'SonarToken', usernameVariable: 'SONAR_USER', passwordVariable: 'SONAR_TOKEN')]) {
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        sh '''
                            SONAR_HOST_URL=${SONAR_HOST_URL:-http://192.168.1.7:9000}
                            sonar-scanner \
                              -Dsonar.projectKey=vuln-bank \
                              -Dsonar.qualitygate.wait=true \
                              -Dsonar.sources=/usr/src \
                              -Dsonar.language=py \
                              -Dsonar.inclusions=**/*.py \
                              -Dsonar.host.url=$SONAR_HOST_URL \
                              -Dsonar.token=$SONAR_TOKEN \
                              -Dsonar.sourceEncoding=UTF-8 2>&1 | tee sonar-scan.json || true
                        '''
                    }
                }
                sh 'cat sonar-scan.json || true'
                archiveArtifacts artifacts: 'sonar-scan.json'
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