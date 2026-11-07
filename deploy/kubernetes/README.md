# HA deployment

`ha.yaml` runs two application instances on distinct nodes, with independent durable encrypted spools, readiness/liveness/startup probes, a disruption budget, unprivileged containers and rolling replacement. StatefulSet volumes retain an instance's spool across replacement. The writable database endpoint must already provide PostgreSQL primary failover; this manifest does not elect database leaders.

Prerequisites: a Kubernetes cluster with at least two worker nodes, a default CSI storage class supporting ReadWriteOnce volumes and node reattachment, a highly available PostgreSQL service, and a TLS ingress/load balancer. Node loss can delay volume reattachment; test the selected storage provider's recovery time. Keep the Service internal and route the existing HTTPS ingress to `vulnstream:8080`.

Create the `vulnstream-runtime` Secret through your secret manager with these keys:

- `DATABASE_URL`: writable HA endpoint for the restricted `vulnstream_app` role.
- `MIGRATION_DATABASE_URL`: the same database with migration-owner credentials. Used only by init containers.
- `ENCRYPTION_KEY`: the existing base64 32-byte encryption key; identical across replicas.
- `APP_ORIGIN`: exact external HTTPS origin.
- `METRICS_TOKEN`: dedicated random token of at least 32 characters.

Build and publish the repository image, then set both StatefulSet images to that immutable version/digest through your deployment tooling. The manifest's `vulnstream-enterprise:local-verified` name is the local build name and must resolve in the cluster before deployment. Apply in the intended namespace with `kubectl apply -f deploy/kubernetes/ha.yaml`. Both init containers use the existing serialized migration runner. The migration owner must be allowed to grant privileges to `vulnstream_app`.

Load the files in `deploy/monitoring` into the existing Prometheus deployment and mount the metrics token at the configured secret path. The listed DNS targets resolve in the application's namespace; use namespace-qualified DNS if Prometheus runs elsewhere. Route the supplied alert rules through your existing Alertmanager receivers. Configure the cluster's stdout collector to retain the application's JSON logs independently of the database. No credentials or alert destinations are embedded in the repository.

The bundled Compose deployment remains a single-host development/small-installation topology. Applying these manifests requires an actual cluster and HA database endpoint; local connectivity tests cannot certify cross-node or primary-promotion availability.

References: [Kubernetes StatefulSet behavior](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/) and [Prometheus scrape authentication](https://prometheus.io/docs/prometheus/latest/configuration/configuration/).
