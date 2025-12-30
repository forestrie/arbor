# ADR-003: Ranger Horizontal Scaling Strategy

## Status

Accepted

## Context

The ranger service is a Cloudflare Queue consumer that runs as a single
`Deployment` replica in the `forestrie-arbor` namespace. The
`clusters/gke-dev/services/ranger/deployment.yaml` manifest sets
`spec.replicas: 1` and there is currently no `HorizontalPodAutoscaler`
resource targeting ranger. Scout and sealer deployments follow the same
pattern and also run as fixed single replicas.

Ranger polls the `forestrie-ingress` Durable Object queue via HTTP. The
consumer uses an exponential backoff loop with these configuration
variables:

- `QUEUE_BATCH_SIZE` (default 100)
- `POLL_INTERVAL_MIN` (minimum poll interval, default 0ms)
- `POLL_INTERVAL` (maximum poll interval, used as `PollIntervalMax`)
- `VISIBILITY_TIMEOUT` (lease duration, default 30s)

On each poll cycle ranger:

1. Issues a pull to the DO with the configured batch size.
2. Processes the returned log groups, with per log group parallelism.
3. Acknowledges committed entries via limit based ack.
4. Resets the poll interval to `POLL_INTERVAL_MIN` when any entries were
   returned.
5. Doubles the interval up to `POLL_INTERVAL_MAX` when the queue was
   empty.

The `ranger-config` ConfigMap sets `POLL_INTERVAL` to `5s` (used as
`PollIntervalMax`) and `POLL_INTERVAL_MIN` to `0s`. When
`POLL_INTERVAL_MIN=0`, ranger re-polls immediately after processing
entries (maximum throughput mode). The backoff logic handles the zero
case by computing a `backoffBase` from `PollIntervalMax/8` (or 10ms if
that is also zero), ensuring exponential backoff still works when the
queue is empty.

Horizontal scaling is desirable when ranger is persistently seeing full
batches on each poll, indicating that the queue backlog is growing
faster than a single consumer can drain it. However, relying solely on
CPU based autoscaling is risky here:

- Ranger spends a significant fraction of time in network bound
  operations (Cloudflare Queue, R2) rather than pure CPU work.
- R2 access is dominated by read and write latency and cryptographic
  verification rather than sustained CPU saturation.
- It is possible to have a growing queue backlog with relatively modest
  pod CPU utilisation, which would not trigger a naive CPU based HPA.

The DO side already assumes a "small many" of ranger pollers. ADR 0007
("Poller Scaling Limits") documents a soft design target of tens to
hundreds of pollers and a hard cap of 500 active pollers enforced in the
queue Durable Object. Any horizontal scaling strategy for ranger must
respect these limits and avoid aggressive misconfiguration that would
drive the number of pollers toward the cap.

## Decision

We introduce a staged horizontal scaling strategy for ranger that
combines conservative cluster level autoscaling with configuration
changes and leaves room for a future queue aware metric.

1. Add a HorizontalPodAutoscaler for ranger based on CPU utilisation
   with a small bounded replica range.
2. Set an explicit non zero `POLL_INTERVAL_MIN` to avoid busy polling
   when the queue is empty while still re polling quickly when there is
   work.
3. Plan a future iteration to expose queue centric metrics (including
   "full batch" signals) from ranger and consider custom metric based
   autoscaling when the metrics stack is in place.

### 1. HorizontalPodAutoscaler for ranger (CPU based)

We will scale ranger using a standard Kubernetes HPA targeting CPU
utilisation. This is compatible with GKE's built in metrics pipeline and
requires no additional infrastructure.

Initial HPA parameters:

- `minReplicas`: 1
- `maxReplicas`: 10
- `targetCPUUtilizationPercentage`: 70% (via `autoscaling/v2` resource
  metrics)

This is intentionally conservative relative to the 500 poller limit in
ADR 0007. Even with future services that also poll the queue, a cap of
10 ranger pods remains far below the Durable Object cap and keeps the
number of active pollers in the tens, not hundreds.

An example manifest that follows the existing `arbor-flux` conventions
would live alongside the ranger deployment under
`clusters/gke-dev/services/ranger/hpa.yaml` and might look like:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ranger
  namespace: forestrie-arbor
  labels:
    app: ranger
    component: queue-consumer
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ranger
  minReplicas: 1
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

The corresponding `kustomization.yaml` under
`clusters/gke-dev/services/ranger` would be updated to include
`hpa.yaml` in `resources`. No changes are required to the ranger
container image.

### 2. Poll interval configuration

The backoff logic now correctly handles `POLL_INTERVAL_MIN=0` by
separating the configured sleep minimum from the backoff base used for
multiplication. This allows `POLL_INTERVAL_MIN=0` to mean "immediate
re-poll on success" while still supporting exponential backoff on empty
responses.

Current values in development:

- `POLL_INTERVAL_MIN`: `0s` (immediate re-poll when entries returned)
- `POLL_INTERVAL`: `5s` (backoff ceiling, used as `PollIntervalMax`)

Behaviour with these values:

- Under load (entries returned): sleep 0, immediate re-poll for maximum
  throughput.
- First empty response: backoff jumps to `PollIntervalMax/8` = 625ms.
- Subsequent empty responses: backoff doubles (625ms → 1.25s → 2.5s →
  5s cap).
- When entries return after idle: reset to 0, immediate re-poll.

The loop always yields to the scheduler via `time.After(sleepDuration)`
even when `sleepDuration=0`, ensuring cooperative multitasking.

For deployments that prefer a minimum poll interval even under load,
`POLL_INTERVAL_MIN` can be set to a non-zero value (e.g., `250ms`).

### 3. Future: queue aware metrics for scaling (Prometheus)

CPU based autoscaling is simple but only an indirect proxy for queue
pressure. A future iteration will add queue aware Prometheus metrics to
ranger, enabling custom metric based HPA that more directly captures
"sustained full batch" conditions.

#### Proposed metrics

The following metrics would be exposed via an HTTP `/metrics` endpoint
suitable for Prometheus scraping, consistent with `arc-services.md`
which already notes `/metrics` as a potential future endpoint:

- `ranger_ingress_polls_total{result="empty|partial|full"}` (Counter):
  Total number of poll cycles, labelled by result. A poll is "full" if
  it returned `QUEUE_BATCH_SIZE` entries, "partial" if it returned
  fewer than `QUEUE_BATCH_SIZE` but more than zero, and "empty" if it
  returned zero entries.

- `ranger_ingress_entries_processed_total` (Counter): Total number of
  entries successfully committed to R2 storage.

- `ranger_ingress_entries_per_poll` (Histogram): Distribution of
  entries returned per poll, useful for understanding batch fullness
  patterns.

- `ranger_ingress_poll_duration_seconds` (Histogram): Time taken for
  each poll cycle including pull, commit, and ack operations.

- `ranger_ingress_commit_duration_seconds` (Histogram): Time taken for
  the R2 commit operation specifically.

- `ranger_ingress_batch_fullness_ratio` (Gauge): Most recent batch
  fullness as a ratio (0.0 to 1.0), calculated as entries returned
  divided by `QUEUE_BATCH_SIZE`. Useful for alerting on sustained full
  batches.

#### Custom metric HPA

Once the metrics are wired into the cluster metrics pipeline (via
Prometheus Adapter or GKE Managed Prometheus), a future HPA revision
could scale on:

- `ranger_ingress_batch_fullness_ratio` averaged across pods, scaling
  up when the ratio exceeds a threshold (e.g., 0.8) for a sustained
  period.
- Rate of `ranger_ingress_polls_total{result="full"}` relative to total
  polls, scaling up when full batches dominate.

This would better match the operational intention of "scale out when
full batches are seen on every poll" while still respecting the poller
limits from ADR 0007.

#### Implementation considerations

- Use the standard Go Prometheus client (`prometheus/client_golang`).
- Register metrics in `main.go` and pass a registry to the consumer.
- Expose `/metrics` on the existing health server port (9090).
- Add a Kubernetes `Service` annotation or `PodMonitor`/
  `ServiceMonitor` resource for Prometheus discovery.
- Consider whether to use GKE Managed Prometheus or self-hosted
  Prometheus depending on cluster configuration.

## Consequences

### Positive

- Ranger can scale out from 1 to 10 replicas automatically under higher
  CPU load, increasing aggregate queue drain capacity.
- `POLL_INTERVAL_MIN=0` with fixed backoff logic provides maximum
  throughput when there is work while still backing off when idle.
- The strategy is compatible with existing manifests and GitOps flow in
  `arbor-flux`.
- Future queue aware metrics are anticipated but not required for the
  initial rollout.

### Negative

- CPU utilisation remains an imperfect proxy for queue backlog; some
  high backlog scenarios may not fully trigger scale out until metrics
  are improved.
- Additional ranger replicas increase the number of active pollers the
  Durable Object must track, although we stay far below the configured
  limit.
- Introducing an HPA adds one more moving part to debug when
  investigating load issues.

### Neutral / Future work

- The same pattern (HPA plus explicit `POLL_INTERVAL_MIN`) can be
  applied to `sealer` once its throughput characteristics are better
  understood.
- If ranger throughput requirements grow significantly we may need to
  revisit both the HPA `maxReplicas` and the Durable Object poller
  limits, guided by ADR 0007 and ADR 0001.

## Implementation Notes

### Completed

1. Fixed backoff logic in `services/ranger/src/consumer/ingress/
   consumer.go` to handle `POLL_INTERVAL_MIN=0` correctly by computing
   a non-zero `backoffBase` for multiplication.
2. Added `POLL_INTERVAL_MIN` to the ConfigMap template in arbor-flux.
3. Configured ranger with `POLL_INTERVAL_MIN=0s` and `POLL_INTERVAL=5s`.

### In progress

1. Add `hpa.yaml` for ranger under `clusters/gke-dev/services/ranger`
   and include it in the kustomization resources.
2. Observe CPU based scaling behaviour under synthetic queue load.

### Future enhancements

1. Add Prometheus metrics to ranger for poll results, batch fullness,
   and commit duration. Expose via `/metrics` endpoint.
2. Configure Prometheus scraping (PodMonitor or ServiceMonitor).
3. Experiment with custom metric based HPA targeting batch fullness.
4. Apply the same HPA pattern to sealer once throughput characteristics
   are understood.
5. Adjust HPA `maxReplicas` and DO poller limits if real world usage
   approaches current caps.
