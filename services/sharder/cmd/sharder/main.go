package main

import (
	apiv1 "github.com/forestrie/arbor/services/sharder/api/v1alpha1"
	"github.com/forestrie/arbor/services/sharder/controllers"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
)

func main() {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = apiv1.AddToScheme(scheme) // only if you have a CRD
	mgr, _ := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme, LeaderElection: true, LeaderElectionID: "shard-operator"})
	_ = (&controllers.PodShardReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr)
	_ = mgr.Start(ctrl.SetupSignalHandler())
}
