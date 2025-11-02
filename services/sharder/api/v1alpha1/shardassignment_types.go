package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ShardAssignment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ShardAssignmentSpec   `json:"spec,omitempty"`
	Status            ShardAssignmentStatus `json:"status,omitempty"`
}

type ShardAssignmentSpec struct {
	OwnerSelector *metav1.LabelSelector `json:"ownerSelector,omitempty"`
	HolderName    string                `json:"holderName,omitempty"`
	HolderUID     string                `json:"holderUID,omitempty"`
}

type ShardAssignmentStatus struct {
	Phase string `json:"phase,omitempty"` // "Unassigned" | "Held"
}

// +kubebuilder:object:root=true
type ShardAssignmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ShardAssignment `json:"items"`
}
