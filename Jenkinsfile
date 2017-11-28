pipeline {
    agent {
        node 'xenial'
    }
    environment {
        ARTIFACTORY = credentials('artifactory-jenkins-local')
    }
    stages {
        stage('Build') {
            sh 'make debs'
        }
        stage('Push') {
            sh 'make upload'
        }
    }
}