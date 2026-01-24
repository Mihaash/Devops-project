pipeline {
    agent any

    tools {
        // Ensure 'Maven 3' and 'JDK 21' are configured in your Jenkins Global Tool Configuration
        maven 'Maven 3' 
        jdk 'JDK 21'
    }

    environment {
        // Define environment variables here
        IMAGE_NAME = 'portfolio-app'
        DOCKER_REGISTRY_CREDENTIALS_ID = 'docker-hub-credentials' // ID of credentials stored in Jenkins
        DOCKER_USER = 'your-dockerhub-username'
    }

    stages {
        stage('Checkout') {
            steps {
                // Get code from the repository
                checkout scm
            }
        }

        stage('Build & Test') {
            steps {
                // Compile and package the application, skipping tests for speed if desired (remove -DskipTests to run them)
                sh 'mvn clean package'
            }
        }

        stage('Unit Tests') {
            steps {
                // Run unit tests and generate reports
                sh 'mvn test'
            }
            post {
                always {
                    // Archiving JUnit test results
                    junit 'target/surefire-reports/*.xml'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    // Build the Docker image
                    sh "docker build -t ${DOCKER_USER}/${IMAGE_NAME}:${BUILD_NUMBER} ."
                    sh "docker build -t ${DOCKER_USER}/${IMAGE_NAME}:latest ."
                }
            }
        }

        /* 
        // Uncomment this stage to push to Docker Hub
        stage('Push Docker Image') {
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: DOCKER_REGISTRY_CREDENTIALS_ID, usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                        sh "echo $PASSWORD | docker login -u $USERNAME --password-stdin"
                        sh "docker push ${DOCKER_USER}/${IMAGE_NAME}:${BUILD_NUMBER}"
                        sh "docker push ${DOCKER_USER}/${IMAGE_NAME}:latest"
                    }
                }
            }
        }
        */
        
        /*
        // Uncomment this stage for deployment (e.g., to a remote server via SSH)
        stage('Deploy') {
            steps {
                // Example: SSH into a server and pull/run the new image
                // sshagent(['your-ssh-credentials-id']) {
                //    sh "ssh user@server 'docker pull ${DOCKER_USER}/${IMAGE_NAME}:latest && docker-compose up -d'"
                // }
                echo 'Deployment stage placeholder'
            }
        }
        */
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
