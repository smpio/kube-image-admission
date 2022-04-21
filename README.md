# kube-image-admission

This [Admission Webhook](https://kubernetes.io/docs/admin/extensible-admission-controllers/#admission-webhooks) modifies Pod container images using user-defined set of rules. It keeps image tag.


## Installation

See [Kubernetes docs](https://kubernetes.io/docs/admin/extensible-admission-controllers/#admission-webhooks).


## Usage

```
-rule EXPR:REPL
-rule ([^/]*):example.com/mirror/$1
-rule docker.io/library/([^/]*):example.com/mirror/$1
```
