pipeline {
    agent any

    tools {
        // Ensure 'Maven 3' and 'JDK 21' are configured in your Jenkins Global Tool Configuration
        maven 'Maven 3' 
        jdk 'JDK 21'
    }

    environment {
        DOCKER_REPO = 'mihaash/portfolio'
        DOCKER_CREDS = 'docker-hub-credentials'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }

        stage('Unit Tests') {
            steps {
                sh 'mvn test'
            }
            post {
                always {
                    junit 'target/surefire-reports/*.xml'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    sh "docker build -t ${DOCKER_REPO}:${BUILD_NUMBER} ."
                    sh "docker tag ${DOCKER_REPO}:${BUILD_NUMBER} ${DOCKER_REPO}:latest"
                }
            }
        }

        stage('Push Docker Image') {
            steps {
                script {
                    withCredentials([
                        usernamePassword(credentialsId: DOCKER_CREDS, usernameVariable: 'USER', passwordVariable: 'PASS')
                    ]) {
                        sh "echo $PASS | docker login -u $USER --password-stdin"
                        sh "docker push ${DOCKER_REPO}:${BUILD_NUMBER}"
                        sh "docker push ${DOCKER_REPO}:latest"
                    }
                }
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                sh "kubectl set image deployment/portfolio-deployment portfolio=${DOCKER_REPO}:latest"
            }
        }
    }

    post {
        success {
            echo 'Pipeline executed successfully!'
        }
        failure {
            echo 'Pipeline failed.'
        }
    }
}
