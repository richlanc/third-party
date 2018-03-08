def artifactoryServer = Artifactory.server 'artifactory-nossl'
def buildInfo = Artifactory.newBuildInfo()
buildInfo.env.capture = true
buildInfo.retention maxBuilds: 10, deleteBuildArtifacts: true

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
                script {
                    def uploadSpec = """{
                        "files": [
                            {
                                "pattern": "out/dists/xenial/main/binary-amd64/*.deb",
                                "props": "deb.distribution=xenial;deb.component=main;deb.architecture=amd64",
                                "target": "debian-local/pool/"
                            }
                        ]
                    }"""
                    artifactoryServer.upload(uploadSpec, buildInfo)
                }
            }
        }
    }
    post {
        success {
            script {
                artifactoryServer.publishBuildInfo buildInfo
            }
        }
    }
}
