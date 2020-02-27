package endpoints

import (
	"fmt"
	"github.com/newrelic/nri-prometheus/internal/pkg/labels"
	"net"
	"net/url"
	"strconv"
	"sync"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/sirupsen/logrus"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

type operatorTargetRetriever struct {
	watching bool
	client   kubernetes.Interface
	targets  *sync.Map
	mclient  monitoringclient.Interface
}

type operatorEvent struct {
	watch.Event
	object metav1.Object
}

type operatorTargetCollection struct {
	targets *sync.Map
	stop    func()
	update  chan operatorEvent
}

type urlBuilder func(host string) url.URL

func defaultUrlBuilder(scheme, port, path string) urlBuilder {
	return func(host string) url.URL {
		if scheme == "" {
			scheme = "http"
		}

		return url.URL{
			Scheme: scheme,
			Host:   net.JoinHostPort(host, port),
			Path:   path,
		}
	}
}
func withInClusterConfig(client kubernetes.Interface) (*operatorTargetRetriever, error) {
	cfg, _ := rest.InClusterConfig()
	mclient, err := monitoringclient.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create prometheus operator client: %w", err)
	}
	return &operatorTargetRetriever{
		client:   client,
		mclient:  mclient,
		watching: false,
		targets:  new(sync.Map),
	}, nil
}

func withKubeConfig(client kubernetes.Interface, kubeConfigFile string) (*operatorTargetRetriever, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return nil, fmt.Errorf("could not read kubeconfig file: %w", err)
	}

	mclient, err := monitoringclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create prometheus operator client: %w", err)
	}
	return &operatorTargetRetriever{
		client:   client,
		mclient:  mclient,
		watching: false,
		targets:  new(sync.Map),
	}, nil
}

func (o *operatorTargetRetriever) foreachNamespace(selector monitoringv1.NamespaceSelector, work func(n *apiv1.Namespace) error) error {
	namespaces, err := o.client.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	matched := map[string]bool{}
	for _, name := range selector.MatchNames {
		matched[name] = true
	}
	for _, n := range namespaces.Items {
		if selector.Any {
			matched[n.Name] = true
		}

		if _, ok := matched[n.Name]; ok {
			err = work(&n)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func mapPorts(containers []apiv1.Container) map[string]string {
	ports := map[string]string{}
	for _, c := range containers {
		for _, port := range c.Ports {
			ports[port.Name] = strconv.Itoa(int(port.ContainerPort))
		}
	}

	return ports
}

func createPodMonitorTargets(pm *monitoringv1.PodMonitor, pod *apiv1.Pod) []Target {
	ports := mapPorts(pod.Spec.Containers)
	targets := make([]Target, len(pm.Spec.PodMetricsEndpoints))
	for i, ep := range pm.Spec.PodMetricsEndpoints {
		path := "metrics"
		if ep.Path != "" {
			path = ep.Path
		}

		if p, ok := ports[ep.Port]; ok {
			targets[i] = podTarget(pod, p, path)
		} else {
			targets[i] = podTarget(pod, "8080", path)
		}

	}

	return targets
}

func mapServicePorts(svc *apiv1.Service) map[string]string {
	m := map[string]string{}
	for _, p := range svc.Spec.Ports {
		m[p.Name] = strconv.Itoa(int(p.Port))
	}

	return m
}

func mapSubsetPorts(subset *apiv1.EndpointSubset) map[string]string {
	m := make(map[string]string)
	for _, p := range subset.Ports {
		m[p.Name] = strconv.Itoa(int(p.Port))
	}

	return m
}

func createServiceMonitorTargets(m *monitoringv1.ServiceMonitor, svc *apiv1.Service) []Target {
	ports := mapServicePorts(svc)
	targets := make([]Target, len(m.Spec.Endpoints))
	for i, ep := range m.Spec.Endpoints {
		path := "metrics"
		if ep.Path != "" {
			path = ep.Path
		}

		if p, ok := ports[ep.Port]; ok {
			targets[i] = serviceTarget(svc, p, path)
		} else {
			targets[i] = serviceTarget(svc, strconv.Itoa(int(svc.Spec.Ports[0].Port)), path)
		}
	}

	return targets
}

func endpointSubsetTarget(ep *apiv1.Endpoints, subset *apiv1.EndpointSubset, builder urlBuilder) []Target {
	targets := make([]Target, 0)
	for _, address := range subset.Addresses {
		lbls := labels.Set{}
		for lk, lv := range ep.Labels {
			lbls["label."+lk] = lv
		}

		lbls["namespaceName"] = ep.Namespace
		var hostname string
		if address.IP == "" {
			hostname = fmt.Sprintf("%s", address.Hostname)
		} else {
			hostname = fmt.Sprintf("%s", address.IP)
		}

		addr := builder(hostname)
		if address.TargetRef != nil {
			if address.TargetRef.Kind == "Pod" {
				lbls["podName"] = address.TargetRef.Name
				if address.NodeName != nil {
					lbls["nodeName"] = *address.NodeName
				}
			}

			targets = append(targets, New(address.TargetRef.Name, addr, Object{Name: ep.Name, Kind: address.TargetRef.Kind, Labels: lbls}))
		} else {
			lbls["serviceName"] = ep.Name
			targets = append(targets, New(ep.Name, addr, Object{Name: ep.Name, Kind: "service", Labels: lbls}))
		}
	}

	return targets
}

func createServiceMonitorEndpointTargets(m *monitoringv1.ServiceMonitor, endpoint *apiv1.Endpoints) []Target {
	targets := make([]Target, 0)
	for _, ep := range m.Spec.Endpoints {
		path := "metrics"
		if ep.Path != "" {
			path = ep.Path
		}
		for _, subset := range endpoint.Subsets {
			if len(subset.Ports) == 0 {
				continue
			}

			ports := mapSubsetPorts(&subset)
			p, ok := ports[ep.Port]
			if ok {
				p = strconv.Itoa(int(subset.Ports[0].Port))
			}

			targets = append(targets, endpointSubsetTarget(endpoint, &subset, defaultUrlBuilder(ep.Scheme, p, path))...)
		}
	}

	return targets
}

func (o *operatorTargetRetriever) watchCustomResource(resource string, watchFunc func() (watch.Interface, error)) {
	for {
		watches, err := watchFunc()
		if err != nil {
			klog.WithError(err).Warnf(
				"couldn't subscribe for %s resource watch, retrying",
				resource,
			)
			continue
		}
		for w := range watches.ResultChan() {
			o.processOperatorEvent(w)
		}
		klog.WithError(err).Warnf(
			"disconnected from %s resource watch, reconnecting",
			resource,
		)
	}
}

func (o *operatorTargetRetriever) watchServiceMonitors() {
	o.watchCustomResource("servicemonitor", func() (watch.Interface, error) {
		return o.mclient.MonitoringV1().ServiceMonitors("").Watch(metav1.ListOptions{})
	})
}

func (o *operatorTargetRetriever) watchPodMonitors() {
	o.watchCustomResource("podmonitor", func() (watch.Interface, error) {
		return o.mclient.MonitoringV1().PodMonitors("").Watch(metav1.ListOptions{})
	})
}

func (o *operatorTargetRetriever) watchOperatorResources() {
	go func() {
		o.watchPodMonitors()
	}()
	go func() {
		o.watchServiceMonitors()
	}()
}

func (o *operatorTargetRetriever) watchCustomResourceItems(
	obj metav1.Object,
	selector monitoringv1.NamespaceSelector,
	labelSelector *metav1.LabelSelector,
	watchCreator func(n *apiv1.Namespace, opt metav1.ListOptions) (watch.Interface, error)) error {

	labelMap, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return err
	}

	c := operatorTargetCollection{
		targets: new(sync.Map),
		stop:    nil,
		update:  make(chan operatorEvent),
	}

	var stopFuncs []func()
	err = o.foreachNamespace(selector, func(n *apiv1.Namespace) error {
		w, err := watchCreator(n, metav1.ListOptions{
			LabelSelector: labelMap.String(),
		})
		if err != nil {
			return err
		}

		go func(u chan operatorEvent) {
			for d := range w.ResultChan() {
				u <- operatorEvent{
					Event:  d,
					object: obj,
				}
			}
		}(c.update)
		stopFuncs = append(stopFuncs, func() {
			w.Stop()
		})
		return nil
	})

	c.stop = func() {
		for _, s := range stopFuncs {
			s()
		}
	}
	if err != nil {
		c.stop()
		return err
	}

	x, ok := o.targets.Load(string(obj.GetUID()))
	o.targets.Store(string(obj.GetUID()), &c)
	if ok {
		if t, ok := x.(*operatorTargetCollection); ok {
			t.stop()
		}
	}

	go func() {
		for evt := range c.update {
			o.processOperatorItemEvent(evt)
		}
	}()

	return nil
}

func (o *operatorTargetRetriever) watchPodMonitor(m *monitoringv1.PodMonitor) error {
	return o.watchCustomResourceItems(m, m.Spec.NamespaceSelector, &m.Spec.Selector, func(n *apiv1.Namespace, opt metav1.ListOptions) (w watch.Interface, err error) {
		return o.client.CoreV1().Pods(n.Name).Watch(opt)
	})
}

func (o *operatorTargetRetriever) watchServiceMonitor(m *monitoringv1.ServiceMonitor) error {
	return o.watchCustomResourceItems(m, m.Spec.NamespaceSelector, &m.Spec.Selector, func(n *apiv1.Namespace, opt metav1.ListOptions) (w watch.Interface, err error) {
		return o.client.CoreV1().Endpoints(n.Name).Watch(opt)
	})
}

func (o *operatorTargetRetriever) replaceTargets(obj metav1.Object, c *operatorTargetCollection) {
	id := string(obj.GetUID())
	if oc, ok := o.targets.Load(id); ok {
		oc.(*operatorTargetCollection).stop()
	}

	o.targets.Store(id, c)
}

func (o *operatorTargetRetriever) handleCustomResourceAddOrUpdate(event watch.Event) {
	switch monitor := event.Object.(type) {
	case *monitoringv1.ServiceMonitor:
		err := o.watchServiceMonitor(monitor)
		if err != nil {
			klog.Errorf("unable to add service monitor targets for %s/%s: %v", monitor.Name, monitor.Namespace, err)
		}

		break
	case *monitoringv1.PodMonitor:
		if err := o.watchPodMonitor(monitor); err != nil {
			klog.Errorf("unable to watch pod monitor targets for %s/%s: %v", monitor.Name, monitor.Namespace, err)
		}
		break
	}
}

func (o *operatorTargetRetriever) processOperatorEvent(event watch.Event) {
	object := event.Object.(metav1.Object)
	_, seen := o.targets.Load(string(object.GetUID()))
	if klog.Level <= logrus.DebugLevel {
		klog.WithFields(logrus.Fields{
			"action": event.Type,
			"name":   object.GetName(),
			"uid":    object.GetUID(),
			"ns":     object.GetNamespace(),
		}).Debug("kubernetes event received")
	}

	// Please, do not try to reduce the amount of code below or simplify the conditionals.
	// This logic is very complex and full of different cases, it's better to be more verbose
	// and have a logic that is easier to reason about.
	switch event.Type {
	case watch.Added:
		if seen && event.Type == watch.Added {
			klog.Debug("skipping previously loaded cusotm resource")
			return
		}
		o.handleCustomResourceAddOrUpdate(event)
		break
	case watch.Modified:
		o.handleCustomResourceAddOrUpdate(event)
		// debugLogEvent(klog, event.Type, "modified", object)
	case watch.Deleted, watch.Error:
		if x, ok := o.targets.Load(string(object.GetUID())); ok {
			if t, ok := x.(*operatorTargetCollection); ok {
				t.stop()
			}
		}

		o.targets.Delete(string(object.GetUID()))
		// debugLogEvent(klog, event.Type, "deleted", object)
	}
}

func (o *operatorTargetRetriever) addOrUpdateV1Event(oc *operatorTargetCollection, evt operatorEvent) {
	object := evt.Object.(metav1.Object)
	switch item := object.(type) {
	case *apiv1.Pod:
		oc.targets.Store(string(item.UID), createPodMonitorTargets(evt.object.(*monitoringv1.PodMonitor), item))
		break
	case *apiv1.Endpoints:
		oc.targets.Store(string(item.UID), createServiceMonitorEndpointTargets(evt.object.(*monitoringv1.ServiceMonitor), item))
	case *apiv1.Service:
		oc.targets.Store(string(item.UID), createServiceMonitorTargets(evt.object.(*monitoringv1.ServiceMonitor), item))
		break
	}
}
func (o *operatorTargetRetriever) processOperatorItemEvent(evt operatorEvent) {
	x, ok := o.targets.Load(string(evt.object.GetUID()))
	if !ok {
		return
	}

	oc, ok := x.(*operatorTargetCollection)
	if !ok {
		return
	}

	object := evt.Object.(metav1.Object)
	_, seen := oc.targets.Load(string(object.GetUID()))
	switch evt.Type {
	case watch.Added:
		if seen {
			klog.Debug("skipping previously loaded pod")
			return
		}

		o.addOrUpdateV1Event(oc, evt)
		break
	case watch.Modified:
		o.addOrUpdateV1Event(oc, evt)
		break
		// debugLogEvent(klog, event.Type, "modified", object)
	case watch.Deleted, watch.Error:
		oc.targets.Delete(string(object.GetUID()))
		// debugLogEvent(klog, event.Type, "deleted", object)
	}
}

func (o *operatorTargetRetriever) listenToUpdates(c chan operatorEvent) {
	for evt := range c {
		o.processOperatorItemEvent(evt)
	}
}

func (o *operatorTargetRetriever) getTargets() []Target {
	length := 0
	o.targets.Range(func(_, _ interface{}) bool {
		length++
		return true
	})
	targets := make([]Target, 0, length)
	o.targets.Range(func(t, y interface{}) bool {
		if coll, ok := y.(*operatorTargetCollection); ok {
			coll.targets.Range(func(_, tgts interface{}) bool {
				targets = append(targets, tgts.([]Target)...)
				return true
			})
		}

		return true
	})

	return targets
}
