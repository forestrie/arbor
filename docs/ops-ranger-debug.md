[2 tools called]

You can temporarily let Kubernetes take over without Flux reconciling by suspending the `ranger` kustomization (namespace `flux-system`), then scale the deployment:

1. Pause Flux for ranger  
   `flux suspend kustomization ranger --namespace flux-system`

2. Scale the workload down (and back up when you’re done)  
   - `kubectl scale deployment/ranger -n forestrie-arbor --replicas=0`  
   - `kubectl scale deployment/ranger -n forestrie-arbor --replicas=1`

3. Resume Flux once finished  
   `flux resume kustomization ranger --namespace flux-system`

While the kustomization is suspended, Flux won’t immediately revert your manual scaling.
