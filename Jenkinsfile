pipeline {
    agent any

    tools {
        maven 'mvn3.9.9'
    }

    environment {
        DOCKER = 'springboot-web-app-pipeline'
        CONTAINER = 'testitpipeline'
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
                sh 'docker build -t $DOCKER:$BUILD_NUMBER .'
            }
        }

        stage('DOCKER REMOVE OLD') {
            steps {
                sh '''
                docker stop $CONTAINER || true
                docker rm $CONTAINER || true
                '''
            }
        }

        stage('DOCKER RUN') {
            steps {
                sh 'docker run -d -p 8080:8080 --name $CONTAINER $DOCKER:$BUILD_NUMBER'
            }
        }
    }
}
