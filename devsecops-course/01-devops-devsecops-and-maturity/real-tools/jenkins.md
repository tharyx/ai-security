# Jenkins: first declarative pipeline (real tool, hedged)

> **Status: hedged outline, not tested by the repo author.** Verify at <https://www.jenkins.io/doc/>. Tests in this repo never need Jenkins (or Java).

**Offline twins (tested):** [pipeline-design](../labs/pipeline-design/README.md). Hardened version and validator fixture: [chapter 2 Jenkins guide](../../02-tools-pipelines-and-secure-sdlc/real-tools/jenkins.md).

## Why you still meet Jenkins

Many enterprises run Jenkins: it is self-hosted, extremely flexible (plugins) and old. That flexibility is also its main risk: plugins, an exposed controller and shared agents have been the root of many incidents. Learn the model, then judge whether a new project should use it.

## Model

- **Controller** schedules and stores config. **Agents** run the work. Do not run builds on the controller.
- **Jenkinsfile** (in the repo) defines the pipeline. Declarative syntax is the readable subset.
- **Credentials store** holds secrets; pipelines refer to credential IDs.

## A first Jenkinsfile

```groovy
pipeline {
  agent none
  stages {
    stage('Audit') {
      agent { docker { image 'node:20' } }       // pin an exact tag or digest in real use
      steps {
        sh 'npm ci --ignore-scripts'
        sh 'npm audit --audit-level=high'
      }
    }
    stage('Deploy') {
      when { branch 'main' }
      agent { label 'deploy' }
      steps {
        input message: 'Release to production?'   // continuous delivery: a person approves
        sh './deploy.sh'
      }
    }
  }
}
```

## Running a lab Jenkins

Use the course lab if it provides one. A local container is the usual route, but **do not expose a test Jenkins to the internet**, keep it on `localhost` and install only the plugins you need. Verify the current LTS release and image name in the Jenkins docs.

## Security notes

- Keep Jenkins core and every plugin updated; subscribe to the Jenkins security advisories.
- Use role-based access, disable anonymous access, require CSRF protection (default in modern versions).
- Bind credentials only where needed (`withCredentials` inside the deploy stage).
- Use ephemeral agents (containers or cloud VMs) so one job cannot read another job's workspace.
