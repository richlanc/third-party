pipeline {
    agent {
        node 'xenial'
    }
    environment {
        ARTIFACTORY = credentials('artifactory-jenkins-local')
    }
    stages {
        stage('Build') {
            steps {
                sh 'make debs'
            }
        }
        stage('Push') {
            steps {
                sh 'make upload'
            }
        }
    }
}
