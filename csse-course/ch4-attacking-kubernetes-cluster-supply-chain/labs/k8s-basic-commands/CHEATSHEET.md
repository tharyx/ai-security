# kubectl cheat sheet (security view)

Learning aid; commands need a cluster. Flags change slowly but check `kubectl <cmd> --help` and your cluster version.

| Task | Command | Security note |
|---|---|---|
| Cluster and context | `kubectl config get-contexts`, `kubectl cluster-info` | Know which cluster you are on before you change anything |
| Who am I allowed to be? | `kubectl auth whoami` (v1.28+), `kubectl auth can-i create pods -n shop`, `kubectl auth can-i --list` | Quick RBAC self-check |
| Check another identity | `kubectl auth can-i get secrets --as system:serviceaccount:shop:web` | Needs impersonate rights |
| List objects | `kubectl get pods -A -o wide`, `kubectl get deploy,svc,ing -n shop` | `-A` for all namespaces |
| Show details | `kubectl describe pod web-abc -n shop` | Events show admission rejections |
| YAML or JSONPath | `kubectl get pod web-abc -o yaml`, `-o jsonpath='{.spec.containers[*].image}'` | Find images and security contexts |
| Create or update | `kubectl apply -f app.yaml`, `kubectl apply -f app.yaml --dry-run=server` | Server dry run runs admission webhooks |
| Diff before apply | `kubectl diff -f app.yaml` | Review changes |
| Logs and exec | `kubectl logs web-abc`, `kubectl exec -it web-abc -- sh` | `exec` needs `pods/exec`, a powerful RBAC verb |
| Port forward | `kubectl port-forward svc/web 8080:80` | Bypasses ingress and NetworkPolicy for the caller |
| Debug | `kubectl debug -it web-abc --image=busybox --target=nginx` | Ephemeral container for distroless images |
| Secrets (careful) | `kubectl get secret db -o jsonpath='{.data.password}' \| base64 -d` | base64 is encoding, not encryption |
| RBAC | `kubectl get roles,rolebindings,clusterroles,clusterrolebindings -A` | Look for wildcards and cluster-admin |
| Service accounts | `kubectl get sa -A`, `kubectl create token web -n shop --duration=10m` | Short-lived bound tokens |
| Rollout | `kubectl rollout status deploy/web`, `kubectl rollout undo deploy/web` | |
| Delete | `kubectl delete -f app.yaml` | Know what the file contains first |
| Explain a field | `kubectl explain pod.spec.securityContext` | Built-in API docs |
| Events and nodes | `kubectl get events -A --sort-by=.lastTimestamp`, `kubectl get nodes -o wide` | |
