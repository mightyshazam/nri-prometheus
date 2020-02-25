module github.com/newrelic/nri-prometheus

go 1.13

require (
	github.com/Bowery/prompt v0.0.0-20190916142128-fa8279994f75 // indirect
	github.com/beorn7/perks v1.0.1
	github.com/coreos/prometheus-operator v0.36.1-0.20200220150036-2fde608b79f9
	github.com/davecgh/go-spew v1.1.1
	github.com/dchest/safefile v0.0.0-20151022103144-855e8d98f185 // indirect
	github.com/evanphx/json-patch v4.5.0+incompatible
	github.com/fsnotify/fsnotify v1.4.8-0.20190312181446-1485a34d5d57
	github.com/gogo/protobuf v1.3.1
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.3.2
	github.com/google/btree v1.0.0
	github.com/google/gofuzz v1.0.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/googleapis/gnostic v0.3.1
	github.com/gregjones/httpcache v0.0.0-20180305231024-9cad4c3443a7
	github.com/hashicorp/hcl v1.0.1-0.20190611123218-cf7d376da96d
	github.com/imdario/mergo v0.3.8
	github.com/json-iterator/go v1.1.8
	github.com/kardianos/govendor v1.0.9 // indirect
	github.com/kelseyhightower/envconfig v1.3.1-0.20170523190722-70f0258d44cb
	github.com/magiconair/properties v1.8.1
	github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/mitchellh/mapstructure v1.1.2
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 v1.0.1
	github.com/newrelic/infra-integrations-sdk v3.3.1+incompatible
	github.com/newrelic/newrelic-telemetry-sdk-go v0.2.1-0.20200116224429-790ff853d12b
	github.com/pelletier/go-toml v1.2.1-0.20181124002727-27c6b39a135b
	github.com/peterbourgon/diskv v2.0.2-0.20180312054125-0646ccaebea1+incompatible
	github.com/pkg/errors v0.8.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/prometheus/client_golang v1.2.1
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/prometheus/common v0.7.0
	github.com/prometheus/procfs v0.0.6
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.2.2
	github.com/spf13/cast v1.3.1-0.20190531093228-c01685bb8421
	github.com/spf13/jwalterweatherman v1.1.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.4.1-0.20190729163700-33bf76add3b7
	github.com/stretchr/objx v0.2.0
	github.com/stretchr/testify v1.5.1
	github.com/subosito/gotenv v1.2.0
	golang.org/x/crypto v0.0.0-20191112222119-e1110fd1c708
	golang.org/x/net v0.0.0-20191112182307-2180aed22343
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sys v0.0.0-20191113165036-4c7a9d0fe056
	golang.org/x/text v0.3.2
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	google.golang.org/appengine v1.6.5
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.2.5
	k8s.io/api v0.0.0-20191115095533-47f6de673b26
	k8s.io/apimachinery v0.0.0-20191115015347-3c7067801da2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kube-openapi v0.0.0-20191107075043-30be4d16710a
	sigs.k8s.io/yaml v1.1.1-0.20181103002144-5fa4c7f5e38d
)

replace (
	github.com/prometheus/prometheus => github.com/prometheus/prometheus v0.0.0-20190818123050-43acd0e2e93f
	k8s.io/api => k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190918161926-8f644eb6e783
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190918160344-1fbdaa4c8d90
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
	k8s.io/klog => k8s.io/klog v0.3.1
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20190228160746-b3a7cee44a30
)
