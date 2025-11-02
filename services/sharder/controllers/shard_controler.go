package controlers

package controllers

import (
  "context"
  corev1 "k8s.io/api/core/v1"
  "k8s.io/apimachinery/pkg/types"
  ctrl "sigs.k8s.io/controller-runtime"
  "sigs.k8s.io/controller-runtime/pkg/client"
  "sigs.k8s.io/controller-runtime/pkg/builder"
  "sigs.k8s.io/controller-runtime/pkg/predicate"
  apiv1 "github.com/forestrie/arboreal/services/sharder/api/v1alpha1"
)

const ShardAnn = "shard.gav.dev/id"

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;patch;update
// +kubebuilder:rbac:groups=yourgroup.io,resources=shardassignments;shardassignments/status,verbs=get;list;watch;update;patch

type PodShardReconciler struct{ client client.Client }

func (r *PodShardReconciler) SetupWithManager(mgr ctrl.Manager) error {
  return ctrl.NewControllerManagedBy(mgr).
    For(&corev1.Pod{}, builder.WithPredicates(
      predicate.NewPredicateFuncs(func(o client.Object) bool {
        return o.GetLabels()["app"] == "writer"
      }),
    )).
    Complete(r)
}

func (r *PodShardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
  var pod corev1.Pod
  if err := r.client.Get(ctx, req.NamespacedName, &pod); err != nil { return ctrl.Result{}, client.IgnoreNotFound(err) }
  if pod.DeletionTimestamp != nil { return r.releaseByUID(ctx, string(pod.UID)) }

  if pod.Annotations[ShardAnn] != "" { return ctrl.Result{}, nil }
  name, ok, err := r.claimOne(ctx, &pod)
  if err != nil || !ok { return ctrl.Result{}, err }
  patch := client.MergeFrom(pod.DeepCopy()); if pod.Annotations == nil { pod.Annotations = map[string]string{} }
  pod.Annotations[ShardAnn] = name
  return ctrl.Result{}, r.client.Patch(ctx, &pod, patch)
}

// claimOne + releaseByUID omitted for brevity (same as earlier sketch)
//
// claimOne tries to atomically claim a free ShardAssignment for the given pod.
// Returns (true, shardName, nil) on success; (false, "", nil) if none available.
func (r *PodShardReconciler) claimOne(ctx context.Context, pod *corev1.Pod) (bool, string, error) {
	var list apiv1.ShardAssignmentList
	if err := r.client.List(ctx, &list); err != nil {
		return false, "", err
	}

	// Deterministic order: smallest name first
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })

	podLbls := labels.Set(pod.Labels)

	for i := range list.Items {
		s := &list.Items[i]

		// Skip claimed
		if s.Spec.HolderUID != "" || s.Spec.HolderName != "" {
			continue
		}

		// Respect owner selector, if present
		if sel := s.Spec.OwnerSelector; sel != nil {
			selector, err := meta.LabelSelectorAsSelector(sel)
			if err != nil || !selector.Matches(podLbls) {
				continue
			}
		}

		// Optimistic claim via Patch(MergeFrom) to honor resourceVersion
		orig := s.DeepCopy()
		s.Spec.HolderName = pod.Name
		s.Spec.HolderUID = string(pod.UID)
		s.Status.Phase = "Held"

		// Optional: keep a finalizer so we can clean up explicitly if you add delete flows
		if s.Finalizers == nil {
			s.Finalizers = []string{}
		}
		hasFinalizer := false
		for _, f := range s.Finalizers {
			if f == Finalizer {
				hasFinalizer = true
				break
			}
		}
		if !hasFinalizer {
			s.Finalizers = append(s.Finalizers, Finalizer)
		}

		if err := r.client.Patch(ctx, s, client.MergeFrom(orig)); err != nil {
			// If someone else won the race, try next shard
			if apierrors.IsConflict(err) {
				continue
			}
			return false, "", err
		}
		return true, s.Name, nil
	}

	// None available
	return false, "", nil
}

// releaseByUID releases any ShardAssignment held by the given Pod UID.
// Best-effort: ignores conflicts and continues.
func (r *PodShardReconciler) releaseByUID(ctx context.Context, podUID string) error {
	var list apiv1.ShardAssignmentList
	if err := r.client.List(ctx, &list); err != nil {
		return err
	}

	for i := range list.Items {
		s := &list.Items[i]
		if s.Spec.HolderUID != podUID {
			continue
		}

		orig := s.DeepCopy()
		s.Spec.HolderUID = ""
		s.Spec.HolderName = ""
		s.Status.Phase = "Unassigned"

		// Remove optional finalizer if present
		out := make([]string, 0, len(s.Finalizers))
		for _, f := range s.Finalizers {
			if f != Finalizer {
				out = append(out, f)
			}
		}
		s.Finalizers = out

		if err := r.client.Patch(ctx, s, client.MergeFrom(orig)); err != nil && !apierrors.IsConflict(err) {
			return err
		}
	}
	return nil
}
