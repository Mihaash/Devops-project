pipeline {
    agent any

    tools {
        maven 'mvn3.9.9'
    }

    environment {
        DOCKER_REGISTRY = 'your-docker-registry' // e.g., 'docker.io/your-username'
        DOCKER_CREDENTIALS_ID = 'your-docker-credentials'
        DOCKER_IMAGE = "${env.DOCKER_REGISTRY}/springboot-web-app-pipeline"
    }

    stages {

        stage('GIT CLONE') {
            steps {
                git branch: 'main',
                    credentialsId: 'github',
                    url: 'https://github.com/Mihaash/Devops-project.git'
            }
        }

        stage('BUILD') {
            steps {
                sh 'mvn clean compile'
            }
        }

        stage('TEST') {
            steps {
                sh 'mvn test'
            }
        }

        stage('PACKAGE') {
            steps {
                sh 'mvn package -DskipTests'
            }
        }

        stage('DOCKER BUILD') {
            steps {
                sh "docker build -t ${env.DOCKER_IMAGE}:${BUILD_NUMBER} ."
            }
        }

        stage('DOCKER PUSH') {
            steps {
                withCredentials([string(credentialsId: env.DOCKER_CREDENTIALS_ID, variable: 'DOCKER_PASSWORD')]) {
                    sh "echo ${DOCKER_PASSWORD} | docker login ${env.DOCKER_REGISTRY} -u your-docker-username --password-stdin"
                    sh "docker push ${env.DOCKER_IMAGE}:${BUILD_NUMBER}"
                }
            }
        }

        stage('DEPLOY TO KUBERNETES') {
            steps {
                sh "sed -i 's|image: .*|image: ${env.DOCKER_IMAGE}:${BUILD_NUMBER}|' deployment.yml"
                sh "kubectl apply -f deployment.yml"
                sh "kubectl apply -f service.yml"
            }
        }
    }
}
