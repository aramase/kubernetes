/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pullmanager

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	kubeletconfiginternal "k8s.io/kubernetes/pkg/kubelet/apis/config"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/util/parsers"
)

var _ ImagePullManager = &PullManager{}

// writeRecordWhileMatchingLimit is a limit at which we stop writing yet-uncached
// records that we found when we were checking if an image pull must be attempted.
// This is to prevent unbounded writes in cases of high namespace turnover.
const writeRecordWhileMatchingLimit = 100

// PullManager is an implementation of the ImagePullManager. It
// tracks images pulled by the kubelet by creating records about ongoing and
// successful pulls.
// It tracks the credentials used with each successful pull in order to be able
// to distinguish tenants requesting access to an image that exists on the kubelet's
// node.
type PullManager struct {
	recordsAccessor PullRecordsAccessor

	imagePolicyEnforcer ImagePullPolicyEnforcer

	imageService kubecontainer.ImageService

	intentAccessors *StripedLockSet // image -> sync.Mutex
	intentCounters  *sync.Map       // image -> number of current in-flight pulls

	pulledAccessors *StripedLockSet // imageRef -> sync.Mutex
}

func NewImagePullManager(ctx context.Context, recordsAccessor PullRecordsAccessor, imagePullPolicy ImagePullPolicyEnforcer, imageService kubecontainer.ImageService, lockStripesNum int32) (*PullManager, error) {
	m := &PullManager{
		recordsAccessor: recordsAccessor,

		imagePolicyEnforcer: imagePullPolicy,

		imageService: imageService,

		intentAccessors: NewStripedLockSet(lockStripesNum),
		intentCounters:  &sync.Map{},

		pulledAccessors: NewStripedLockSet(lockStripesNum),
	}

	m.initialize(ctx)

	return m, nil
}

func (f *PullManager) RecordPullIntent(image string) error {
	f.intentAccessors.Lock(image)
	defer f.intentAccessors.Unlock(image)

	if err := f.recordsAccessor.WriteImagePullIntent(image); err != nil {
		return fmt.Errorf("failed to record image pull intent: %w", err)
	}

	f.incrementIntentCounterForImage(image)
	return nil
}

func (f *PullManager) RecordImagePulled(image, imageRef string, credentials *kubeletconfiginternal.ImagePullCredentials) {
	if err := f.writePulledRecordIfChanged(image, imageRef, credentials); err != nil {
		klog.ErrorS(err, "failed to write image pulled record", "imageRef", imageRef)
		return
	}

	// Notice we don't decrement in case of record write error, which leaves dangling
	// imagePullIntents and refCount in the intentCounters map.
	// This is done so that the successfully pulled image is still considered as pulled by the kubelet.
	// The kubelet will attempt to turn the imagePullIntent into a pulled record again when
	// it's restarted.
	f.decrementImagePullIntent(image)
}

// writePulledRecordIfChanged writes an ImagePulledRecord into the f.pulledDir directory.
// `image` is an image from a container of a Pod object.
// `imageRef` is a reference to the `image“ as used by the CRI.
// `credentials` is a set of credentials that should be written to a new/merged into
// an existing record.
//
// If `credentials` is nil, it marks a situation where an image was pulled under
// unknown circumstances. We should record the image as tracked but no credentials
// should be written in order to force credential verification when the image is
// accessed the next time.
func (f *PullManager) writePulledRecordIfChanged(image, imageRef string, credentials *kubeletconfiginternal.ImagePullCredentials) error {
	f.pulledAccessors.Lock(imageRef)
	defer f.pulledAccessors.Unlock(imageRef)

	sanitizedImage, err := trimImageTagDigest(image)
	if err != nil {
		return fmt.Errorf("invalid image name %q: %w", image, err)
	}

	pulledRecord, _, err := f.recordsAccessor.GetImagePulledRecord(imageRef)
	if err != nil {
		klog.InfoS("failed to retrieve an ImagePulledRecord", "image", image, "err", err)
		pulledRecord = nil
	}

	var pulledRecordChanged bool
	if pulledRecord == nil {
		pulledRecordChanged = true
		pulledRecord = &kubeletconfiginternal.ImagePulledRecord{
			LastUpdatedTime:   metav1.Time{Time: time.Now()},
			ImageRef:          imageRef,
			CredentialMapping: make(map[string]kubeletconfiginternal.ImagePullCredentials),
		}
		// just the existence of the pulled record for a given imageRef is enough
		// for us to consider it kubelet-pulled. The kubelet should fail safe
		// if it does not find a credential record for the specific image, and it
		// must require credential validation
		if credentials != nil {
			pulledRecord.CredentialMapping[sanitizedImage] = *credentials
		}
	} else {
		pulledRecord, pulledRecordChanged = pulledRecordMergeNewCreds(pulledRecord, sanitizedImage, credentials)
	}

	if !pulledRecordChanged {
		return nil
	}

	return f.recordsAccessor.WriteImagePulledRecord(pulledRecord)
}

func (f *PullManager) RecordImagePullFailed(image string) {
	f.decrementImagePullIntent(image)
}

// decrementImagePullIntent decreses the number of how many times image pull
// intent for a given `image` was requested, and removes the ImagePullIntent file
// if the reference counter for the image reaches zero.
func (f *PullManager) decrementImagePullIntent(image string) {
	f.intentAccessors.Lock(image)
	defer f.intentAccessors.Unlock(image)

	if f.getIntentCounterForImage(image) <= 1 {
		if err := f.recordsAccessor.DeleteImagePullIntent(image); err != nil {
			klog.ErrorS(err, "failed to remove image pull intent", "image", image)
			return
		}
		// only delete the intent counter once the file was deleted to be consistent
		// with the records
		f.intentCounters.Delete(image)
		return
	}

	f.decrementIntentCounterForImage(image)
}

func (f *PullManager) MustAttemptImagePull(image, imageRef string, podSecrets []kubeletconfiginternal.ImagePullSecret) bool {
	// Convert legacy call to new method
	credentials := &kubeletconfiginternal.ImagePullCredentials{
		KubernetesSecrets: podSecrets,
	}
	return f.MustAttemptImagePullWithCredentials(image, imageRef, credentials)
}

func (f *PullManager) MustAttemptImagePullWithCredentials(image, imageRef string, credentials *kubeletconfiginternal.ImagePullCredentials) bool {
	if len(imageRef) == 0 {
		return true
	}

	var imagePulledByKubelet bool
	var pulledRecord *kubeletconfiginternal.ImagePulledRecord

	err := func() error {
		// don't allow changes to the files we're using for our decision
		f.pulledAccessors.Lock(imageRef)
		defer f.pulledAccessors.Unlock(imageRef)
		f.intentAccessors.Lock(image)
		defer f.intentAccessors.Unlock(image)

		var err error
		var exists bool
		pulledRecord, exists, err = f.recordsAccessor.GetImagePulledRecord(imageRef)
		switch {
		case err != nil:
			return err
		case exists:
			imagePulledByKubelet = true
		case pulledRecord != nil:
			imagePulledByKubelet = true
		default:
			// optimized check - we can check the intent number, however, if it's zero
			// it may only mean kubelet restarted since writing the intent record and
			// we must fall back to the actual cache
			imagePulledByKubelet = f.getIntentCounterForImage(image) > 0
			if imagePulledByKubelet {
				break
			}

			if exists, err := f.recordsAccessor.ImagePullIntentExists(image); err != nil {
				return fmt.Errorf("failed to check existence of an image pull intent: %w", err)
			} else if exists {
				imagePulledByKubelet = true
			}
		}

		return nil
	}()

	if err != nil {
		klog.ErrorS(err, "Unable to access cache records about image pulls")
		return true
	}

	if !f.imagePolicyEnforcer.RequireCredentialVerificationForImage(image, imagePulledByKubelet) {
		return false
	}

	if pulledRecord == nil {
		// we have no proper records of the image being pulled in the past, we can short-circuit here
		return true
	}

	sanitizedImage, err := trimImageTagDigest(image)
	if err != nil {
		klog.ErrorS(err, "failed to parse image name, forcing image credentials reverification", "image", sanitizedImage)
		return true
	}

	cachedCreds, ok := pulledRecord.CredentialMapping[sanitizedImage]
	if !ok {
		return true
	}

	if cachedCreds.NodePodsAccessible {
		// anyone on this node can access the image
		return false
	}

	// Check if any of the provided credentials match the cached ones
	return !f.credentialsMatch(credentials, &cachedCreds, image, imageRef)
}

// credentialsMatch checks if any of the provided credentials match the cached credentials
func (f *PullManager) credentialsMatch(providedCreds, cachedCreds *kubeletconfiginternal.ImagePullCredentials, image, imageRef string) bool {
	currentTime := time.Now()

	// Check Kubernetes secrets
	if f.kubernetesSecretsMatch(providedCreds.KubernetesSecrets, cachedCreds.KubernetesSecrets, image, imageRef) {
		return true
	}

	// Check service account credentials
	if f.serviceAccountCredentialsMatch(providedCreds.ServiceAccountCredentials, cachedCreds.ServiceAccountCredentials, currentTime, image, imageRef) {
		return true
	}

	// Check pod-level service account credentials
	if f.podServiceAccountCredentialsMatch(providedCreds.PodServiceAccountCredentials, cachedCreds.PodServiceAccountCredentials, currentTime, image, imageRef) {
		return true
	}

	return false
}

// kubernetesSecretsMatch checks if any provided Kubernetes secrets match cached ones
func (f *PullManager) kubernetesSecretsMatch(providedSecrets, cachedSecrets []kubeletconfiginternal.ImagePullSecret, image, imageRef string) bool {
	if len(cachedSecrets) == 0 {
		return false
	}

	for _, podSecret := range providedSecrets {
		for _, cachedSecret := range cachedSecrets {
			// we need to check hash len in case hashing failed while storing the record in the keyring
			hashesMatch := len(cachedSecret.CredentialHash) > 0 && podSecret.CredentialHash == cachedSecret.CredentialHash
			secretCoordinatesMatch := podSecret.UID == cachedSecret.UID &&
				podSecret.Namespace == cachedSecret.Namespace &&
				podSecret.Name == cachedSecret.Name

			if hashesMatch {
				if !secretCoordinatesMatch && len(cachedSecrets) < writeRecordWhileMatchingLimit {
					// While we're only matching at this point, we want to ensure this secret is considered valid in the future
					// and so we make an additional write to the cache.
					// writePulledRecord() is a noop in case the secret with the updated hash already appears in the cache.
					if err := f.writePulledRecordIfChanged(image, imageRef, &kubeletconfiginternal.ImagePullCredentials{KubernetesSecrets: []kubeletconfiginternal.ImagePullSecret{podSecret}}); err != nil {
						klog.ErrorS(err, "failed to write an image pulled record", "image", image, "imageRef", imageRef)
					}
				}
				return true
			}

			if secretCoordinatesMatch {
				if !hashesMatch && len(cachedSecrets) < writeRecordWhileMatchingLimit {
					// While we're only matching at this point, we want to ensure the updated credentials are considered valid in the future
					// and so we make an additional write to the cache.
					// writePulledRecord() is a noop in case the hash got updated in the meantime.
					if err := f.writePulledRecordIfChanged(image, imageRef, &kubeletconfiginternal.ImagePullCredentials{KubernetesSecrets: []kubeletconfiginternal.ImagePullSecret{podSecret}}); err != nil {
						klog.ErrorS(err, "failed to write an image pulled record", "image", image, "imageRef", imageRef)
					}
					return true
				}
			}
		}
	}

	return false
}

// serviceAccountCredentialsMatch checks if any provided service account credentials match cached ones
func (f *PullManager) serviceAccountCredentialsMatch(providedCreds, cachedCreds []kubeletconfiginternal.ServiceAccountCredential, currentTime time.Time, image, imageRef string) bool {
	if len(cachedCreds) == 0 {
		return false
	}

	for _, providedCred := range providedCreds {
		for _, cachedCred := range cachedCreds {
			// Check if the cached credential has expired
			if !cachedCred.ExpiresAt.IsZero() && currentTime.After(cachedCred.ExpiresAt.Time) {
				continue // Skip expired credentials
			}

			// Match service account coordinates and token hash
			if providedCred.ServiceAccountName == cachedCred.ServiceAccountName &&
				providedCred.ServiceAccountNamespace == cachedCred.ServiceAccountNamespace &&
				providedCred.ServiceAccountUID == cachedCred.ServiceAccountUID &&
				providedCred.TokenHash == cachedCred.TokenHash {

				// Update cache with newer expiration if needed
				if !providedCred.ExpiresAt.IsZero() && (cachedCred.ExpiresAt.IsZero() || providedCred.ExpiresAt.Time.After(cachedCred.ExpiresAt.Time)) {
					if len(cachedCreds) < writeRecordWhileMatchingLimit {
						if err := f.writePulledRecordIfChanged(image, imageRef, &kubeletconfiginternal.ImagePullCredentials{ServiceAccountCredentials: []kubeletconfiginternal.ServiceAccountCredential{providedCred}}); err != nil {
							klog.ErrorS(err, "failed to write an image pulled record with updated service account credential", "image", image, "imageRef", imageRef)
						}
					}
				}
				return true
			}
		}
	}

	return false
}

// podServiceAccountCredentialsMatch checks if any provided pod-level service account credentials match cached ones
func (f *PullManager) podServiceAccountCredentialsMatch(providedCreds, cachedCreds []kubeletconfiginternal.PodServiceAccountCredential, currentTime time.Time, image, imageRef string) bool {
	if len(cachedCreds) == 0 {
		return false
	}

	for _, providedCred := range providedCreds {
		for _, cachedCred := range cachedCreds {
			// Check if the cached credential has expired
			if !cachedCred.ExpiresAt.IsZero() && currentTime.After(cachedCred.ExpiresAt.Time) {
				continue // Skip expired credentials
			}

			// Match pod and service account coordinates and token hash
			if providedCred.PodName == cachedCred.PodName &&
				providedCred.PodNamespace == cachedCred.PodNamespace &&
				providedCred.PodUID == cachedCred.PodUID &&
				providedCred.ServiceAccountName == cachedCred.ServiceAccountName &&
				providedCred.ServiceAccountNamespace == cachedCred.ServiceAccountNamespace &&
				providedCred.ServiceAccountUID == cachedCred.ServiceAccountUID &&
				providedCred.TokenHash == cachedCred.TokenHash {

				// Update cache with newer expiration if needed
				if !providedCred.ExpiresAt.IsZero() && (cachedCred.ExpiresAt.IsZero() || providedCred.ExpiresAt.Time.After(cachedCred.ExpiresAt.Time)) {
					if len(cachedCreds) < writeRecordWhileMatchingLimit {
						if err := f.writePulledRecordIfChanged(image, imageRef, &kubeletconfiginternal.ImagePullCredentials{PodServiceAccountCredentials: []kubeletconfiginternal.PodServiceAccountCredential{providedCred}}); err != nil {
							klog.ErrorS(err, "failed to write an image pulled record with updated pod service account credential", "image", image, "imageRef", imageRef)
						}
					}
				}
				return true
			}
		}
	}

	return false
}

func (f *PullManager) PruneUnknownRecords(imageList []string, until time.Time) {
	f.pulledAccessors.GlobalLock()
	defer f.pulledAccessors.GlobalUnlock()

	pulledRecords, err := f.recordsAccessor.ListImagePulledRecords()
	if err != nil {
		klog.ErrorS(err, "there were errors listing ImagePulledRecords, garbage collection will proceed with incomplete records list")
	}

	imagesInUse := sets.New(imageList...)
	for _, imageRecord := range pulledRecords {
		if !imageRecord.LastUpdatedTime.Time.Before(until) {
			// the image record was only updated after the GC started
			continue
		}

		if imagesInUse.Has(imageRecord.ImageRef) {
			continue
		}

		if err := f.recordsAccessor.DeleteImagePulledRecord(imageRecord.ImageRef); err != nil {
			klog.ErrorS(err, "failed to remove an ImagePulledRecord", "imageRef", imageRecord.ImageRef)
		}
	}

}

// initialize gathers all the images from pull intent records that exist
// from the previous kubelet runs.
// If the CRI reports any of the above images as already pulled, we turn the
// pull intent into a pulled record and the original pull intent is deleted.
//
// This method is not thread-safe and it should only be called upon the creation
// of the PullManager.
func (f *PullManager) initialize(ctx context.Context) {
	pullIntents, err := f.recordsAccessor.ListImagePullIntents()
	if err != nil {
		klog.ErrorS(err, "there were errors listing ImagePullIntents, continuing with an incomplete records list")
	}

	if len(pullIntents) == 0 {
		return
	}

	imageObjs, err := f.imageService.ListImages(ctx)
	if err != nil {
		klog.ErrorS(err, "failed to list images")
	}

	inFlightPulls := sets.New[string]()
	for _, intent := range pullIntents {
		inFlightPulls.Insert(intent.Image)
	}

	// Each of the images known to the CRI might consist of multiple tags and digests,
	// which is what we track in the ImagePullIntent - we need to go through all of these
	// for each image.
	for _, imageObj := range imageObjs {
		existingRecordedImages := searchForExistingTagDigest(inFlightPulls, imageObj)

		for _, image := range existingRecordedImages.UnsortedList() {

			if err := f.writePulledRecordIfChanged(image, imageObj.ID, nil); err != nil {
				klog.ErrorS(err, "failed to write an image pull record", "imageRef", imageObj.ID)
				continue
			}

			if err := f.recordsAccessor.DeleteImagePullIntent(image); err != nil {
				klog.V(2).InfoS("failed to remove image pull intent file", "imageName", image, "error", err)
			}
		}
	}

}

func (f *PullManager) incrementIntentCounterForImage(image string) {
	f.intentCounters.Store(image, f.getIntentCounterForImage(image)+1)
}
func (f *PullManager) decrementIntentCounterForImage(image string) {
	f.intentCounters.Store(image, f.getIntentCounterForImage(image)-1)
}

func (f *PullManager) getIntentCounterForImage(image string) int32 {
	intentNumAny, ok := f.intentCounters.Load(image)
	if !ok {
		return 0
	}
	intentNum, ok := intentNumAny.(int32)
	if !ok {
		panic(fmt.Sprintf("expected the intentCounters sync map to only contain int32 values, got %T", intentNumAny))
	}
	return intentNum
}

// searchForExistingTagDigest loops through the `image` RepoDigests and RepoTags
// and tries to find all image digests/tags in `inFlightPulls`, which is a map of
// containerImage -> pulling intent path.
func searchForExistingTagDigest(inFlightPulls sets.Set[string], image kubecontainer.Image) sets.Set[string] {
	existingRecordedImages := sets.New[string]()
	for _, digest := range image.RepoDigests {
		if ok := inFlightPulls.Has(digest); ok {
			existingRecordedImages.Insert(digest)
		}
	}

	for _, tag := range image.RepoTags {
		if ok := inFlightPulls.Has(tag); ok {
			existingRecordedImages.Insert(tag)
		}
	}

	return existingRecordedImages
}

type kubeSecretCoordinates struct {
	UID       string
	Namespace string
	Name      string
}

// pulledRecordMergeNewCreds merges the credentials from `newCreds` into the `orig`
// record for the `imageNoTagDigest` image.
// `imageNoTagDigest` is the content of the `image` field from a pod's container
// after any tag or digest were removed from it.
//
// NOTE: pulledRecordMergeNewCreds() may be often called in the read path of
// PullManager.MustAttemptImagePul() and so it's desirable to limit allocations
// (e.g. DeepCopy()) until it is necessary.
func pulledRecordMergeNewCreds(orig *kubeletconfiginternal.ImagePulledRecord, imageNoTagDigest string, newCreds *kubeletconfiginternal.ImagePullCredentials) (*kubeletconfiginternal.ImagePulledRecord, bool) {
	if newCreds == nil {
		// no new credential information to record
		return orig, false
	}

	if !newCreds.NodePodsAccessible && len(newCreds.KubernetesSecrets) == 0 &&
		len(newCreds.ServiceAccountCredentials) == 0 && len(newCreds.PodServiceAccountCredentials) == 0 {
		// we don't have any secret credentials, service account credentials, or node-wide access to record
		return orig, false
	}
	selectedCreds, found := orig.CredentialMapping[imageNoTagDigest]
	if !found {
		ret := orig.DeepCopy()
		if ret.CredentialMapping == nil {
			ret.CredentialMapping = make(map[string]kubeletconfiginternal.ImagePullCredentials)
		}
		ret.CredentialMapping[imageNoTagDigest] = *newCreds
		ret.LastUpdatedTime = metav1.Time{Time: time.Now()}
		return ret, true
	}

	if selectedCreds.NodePodsAccessible {
		return orig, false
	}

	if newCreds.NodePodsAccessible {
		selectedCreds.NodePodsAccessible = true
		selectedCreds.KubernetesSecrets = nil
		selectedCreds.ServiceAccountCredentials = nil
		selectedCreds.PodServiceAccountCredentials = nil

		ret := orig.DeepCopy()
		ret.CredentialMapping[imageNoTagDigest] = selectedCreds
		ret.LastUpdatedTime = metav1.Time{Time: time.Now()}
		return ret, true
	}

	var secretsChanged bool
	var serviceAccountCredsChanged bool
	var podServiceAccountCredsChanged bool

	selectedCreds.KubernetesSecrets, secretsChanged = mergePullSecrets(selectedCreds.KubernetesSecrets, newCreds.KubernetesSecrets)
	selectedCreds.ServiceAccountCredentials, serviceAccountCredsChanged = mergeServiceAccountCredentials(selectedCreds.ServiceAccountCredentials, newCreds.ServiceAccountCredentials)
	selectedCreds.PodServiceAccountCredentials, podServiceAccountCredsChanged = mergePodServiceAccountCredentials(selectedCreds.PodServiceAccountCredentials, newCreds.PodServiceAccountCredentials)

	if !secretsChanged && !serviceAccountCredsChanged && !podServiceAccountCredsChanged {
		return orig, false
	}

	ret := orig.DeepCopy()
	ret.CredentialMapping[imageNoTagDigest] = selectedCreds
	ret.LastUpdatedTime = metav1.Time{Time: time.Now()}
	return ret, true
}

// mergePullSecrets merges two slices of ImagePullSecret object into one while
// keeping the objects unique per `Namespace, Name, UID` key.
//
// In case an object from the `new` slice has the same `Namespace, Name, UID` combination
// as an object from `orig`, the result will use the CredentialHash value of the
// object from `new`.
//
// The returned slice is sorted by Namespace, Name and UID (in this order). Also
// returns an indicator whether the set of input secrets chaged.
func mergePullSecrets(orig, new []kubeletconfiginternal.ImagePullSecret) ([]kubeletconfiginternal.ImagePullSecret, bool) {
	credSet := make(map[kubeSecretCoordinates]string)
	for _, secret := range orig {
		credSet[kubeSecretCoordinates{
			UID:       secret.UID,
			Namespace: secret.Namespace,
			Name:      secret.Name,
		}] = secret.CredentialHash
	}

	changed := false
	for _, s := range new {
		key := kubeSecretCoordinates{UID: s.UID, Namespace: s.Namespace, Name: s.Name}
		if existingHash, ok := credSet[key]; !ok || existingHash != s.CredentialHash {
			changed = true
			credSet[key] = s.CredentialHash
		}
	}
	if !changed {
		return orig, false
	}

	ret := make([]kubeletconfiginternal.ImagePullSecret, 0, len(credSet))
	for coords, hash := range credSet {
		ret = append(ret, kubeletconfiginternal.ImagePullSecret{
			UID:            coords.UID,
			Namespace:      coords.Namespace,
			Name:           coords.Name,
			CredentialHash: hash,
		})
	}
	// we don't need to use the stable version because secret coordinates used for ordering are unique in the set
	slices.SortFunc(ret, imagePullSecretLess)

	return ret, true
}

// mergeServiceAccountCredentials merges two slices of ServiceAccountCredential object into one while
// keeping the objects unique per service account coordinates and token hash.
//
// In case an object from the `new` slice has the same service account coordinates and token hash
// as an object from `orig`, the result will use the ExpiresAt value from the newer one.
//
// The returned slice is sorted by ServiceAccountNamespace, ServiceAccountName, ServiceAccountUID, and TokenHash (in this order). Also
// returns an indicator whether the set of input credentials changed.
func mergeServiceAccountCredentials(orig, new []kubeletconfiginternal.ServiceAccountCredential) ([]kubeletconfiginternal.ServiceAccountCredential, bool) {
	type serviceAccountCoordinates struct {
		ServiceAccountUID       string
		ServiceAccountNamespace string
		ServiceAccountName      string
		TokenHash               string
	}

	credMap := make(map[serviceAccountCoordinates]metav1.Time)
	for _, cred := range orig {
		credMap[serviceAccountCoordinates{
			ServiceAccountUID:       cred.ServiceAccountUID,
			ServiceAccountNamespace: cred.ServiceAccountNamespace,
			ServiceAccountName:      cred.ServiceAccountName,
			TokenHash:               cred.TokenHash,
		}] = cred.ExpiresAt
	}

	changed := false
	for _, cred := range new {
		key := serviceAccountCoordinates{
			ServiceAccountUID:       cred.ServiceAccountUID,
			ServiceAccountNamespace: cred.ServiceAccountNamespace,
			ServiceAccountName:      cred.ServiceAccountName,
			TokenHash:               cred.TokenHash,
		}
		if existingExpiry, ok := credMap[key]; !ok || (!cred.ExpiresAt.IsZero() && (existingExpiry.IsZero() || cred.ExpiresAt.Time.After(existingExpiry.Time))) {
			changed = true
			credMap[key] = cred.ExpiresAt
		}
	}
	if !changed {
		return orig, false
	}

	ret := make([]kubeletconfiginternal.ServiceAccountCredential, 0, len(credMap))
	for coords, expiresAt := range credMap {
		ret = append(ret, kubeletconfiginternal.ServiceAccountCredential{
			ServiceAccountUID:       coords.ServiceAccountUID,
			ServiceAccountNamespace: coords.ServiceAccountNamespace,
			ServiceAccountName:      coords.ServiceAccountName,
			TokenHash:               coords.TokenHash,
			ExpiresAt:               expiresAt,
		})
	}
	// we don't need to use the stable version because service account coordinates used for ordering are unique in the set
	slices.SortFunc(ret, serviceAccountCredentialLess)

	return ret, true
}

// mergePodServiceAccountCredentials merges two slices of PodServiceAccountCredential object into one while
// keeping the objects unique per pod and service account coordinates and token hash.
//
// In case an object from the `new` slice has the same coordinates and token hash
// as an object from `orig`, the result will use the ExpiresAt value from the newer one.
//
// The returned slice is sorted by pod and service account coordinates. Also
// returns an indicator whether the set of input credentials changed.
func mergePodServiceAccountCredentials(orig, new []kubeletconfiginternal.PodServiceAccountCredential) ([]kubeletconfiginternal.PodServiceAccountCredential, bool) {
	type podServiceAccountCoordinates struct {
		PodUID                  string
		PodNamespace            string
		PodName                 string
		ServiceAccountUID       string
		ServiceAccountNamespace string
		ServiceAccountName      string
		TokenHash               string
	}

	credMap := make(map[podServiceAccountCoordinates]metav1.Time)
	for _, cred := range orig {
		credMap[podServiceAccountCoordinates{
			PodUID:                  cred.PodUID,
			PodNamespace:            cred.PodNamespace,
			PodName:                 cred.PodName,
			ServiceAccountUID:       cred.ServiceAccountUID,
			ServiceAccountNamespace: cred.ServiceAccountNamespace,
			ServiceAccountName:      cred.ServiceAccountName,
			TokenHash:               cred.TokenHash,
		}] = cred.ExpiresAt
	}

	changed := false
	for _, cred := range new {
		key := podServiceAccountCoordinates{
			PodUID:                  cred.PodUID,
			PodNamespace:            cred.PodNamespace,
			PodName:                 cred.PodName,
			ServiceAccountUID:       cred.ServiceAccountUID,
			ServiceAccountNamespace: cred.ServiceAccountNamespace,
			ServiceAccountName:      cred.ServiceAccountName,
			TokenHash:               cred.TokenHash,
		}
		if existingExpiry, ok := credMap[key]; !ok || (!cred.ExpiresAt.IsZero() && (existingExpiry.IsZero() || cred.ExpiresAt.Time.After(existingExpiry.Time))) {
			changed = true
			credMap[key] = cred.ExpiresAt
		}
	}
	if !changed {
		return orig, false
	}

	ret := make([]kubeletconfiginternal.PodServiceAccountCredential, 0, len(credMap))
	for coords, expiresAt := range credMap {
		ret = append(ret, kubeletconfiginternal.PodServiceAccountCredential{
			PodUID:                  coords.PodUID,
			PodNamespace:            coords.PodNamespace,
			PodName:                 coords.PodName,
			ServiceAccountUID:       coords.ServiceAccountUID,
			ServiceAccountNamespace: coords.ServiceAccountNamespace,
			ServiceAccountName:      coords.ServiceAccountName,
			TokenHash:               coords.TokenHash,
			ExpiresAt:               expiresAt,
		})
	}
	// we don't need to use the stable version because coordinates used for ordering are unique in the set
	slices.SortFunc(ret, podServiceAccountCredentialLess)

	return ret, true
}

// serviceAccountCredentialLess is a helper function to define ordering in a slice of
// ServiceAccountCredential objects.
func serviceAccountCredentialLess(a, b kubeletconfiginternal.ServiceAccountCredential) int {
	if cmp := strings.Compare(a.ServiceAccountNamespace, b.ServiceAccountNamespace); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.ServiceAccountName, b.ServiceAccountName); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.ServiceAccountUID, b.ServiceAccountUID); cmp != 0 {
		return cmp
	}

	return strings.Compare(a.TokenHash, b.TokenHash)
}

// podServiceAccountCredentialLess is a helper function to define ordering in a slice of
// PodServiceAccountCredential objects.
func podServiceAccountCredentialLess(a, b kubeletconfiginternal.PodServiceAccountCredential) int {
	if cmp := strings.Compare(a.PodNamespace, b.PodNamespace); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.PodName, b.PodName); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.PodUID, b.PodUID); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.ServiceAccountNamespace, b.ServiceAccountNamespace); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.ServiceAccountName, b.ServiceAccountName); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.ServiceAccountUID, b.ServiceAccountUID); cmp != 0 {
		return cmp
	}

	return strings.Compare(a.TokenHash, b.TokenHash)
}

// imagePullSecretLess is a helper function to define ordering in a slice of
// ImagePullSecret objects.
func imagePullSecretLess(a, b kubeletconfiginternal.ImagePullSecret) int {
	if cmp := strings.Compare(a.Namespace, b.Namespace); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
		return cmp
	}

	return strings.Compare(a.UID, b.UID)
}

// trimImageTagDigest removes the tag and digest from an image name
func trimImageTagDigest(containerImage string) (string, error) {
	imageName, _, _, err := parsers.ParseImageName(containerImage)
	return imageName, err
}
