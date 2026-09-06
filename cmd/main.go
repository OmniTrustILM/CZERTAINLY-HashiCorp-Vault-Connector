package main

import (
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/authority"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/config"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/connectorInfo"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/discovery"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/health"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret"
	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/utils"

	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/yuseferi/zax/v2"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

var version = "dev"

var routes map[string][]model.EndpointDto

var log = logger.Get()

func main() {
	routes = make(map[string][]model.EndpointDto)
	c := config.Get()
	log.Info("Starting HashiCorp-Vault-Connector", zap.String("version", version))
	conn, _ := db.ConnectDB(c)
	schema := config.Get().Database.Schema

	err := conn.Exec("CREATE SCHEMA IF NOT EXISTS " + pq.QuoteIdentifier(schema)).Error
	if err != nil {
		log.Error("Error creating schema", zap.Error(err))
	}

	err = conn.Exec("SET search_path TO " + pq.QuoteIdentifier(schema)).Error
	if err != nil {
		log.Error("Error setting search_path", zap.Error(err))
	}

	db.MigrateDB(c, conn)
	discoveryRepo, _ := db.NewDiscoveryRepository(conn)
	authorityRepo, _ := db.NewAuthorityRepository(conn)

	DiscoveryAPIService := discovery.NewDiscoveryAPIService(discoveryRepo, authorityRepo, log)
	DiscoveryAPIController := discovery.NewDiscoveryAPIController(DiscoveryAPIService)

	AuthorityManagementAPIService := authority.NewAuthorityManagementAPIService(authorityRepo, log)
	AuthorityManagementAPIController := authority.NewAuthorityManagementAPIController(AuthorityManagementAPIService)

	CertificateManagementAPIService := authority.NewCertificateManagementAPIService(authorityRepo, log)
	CertificateManagementAPIController := authority.NewCertificateManagementAPIController(CertificateManagementAPIService)

	DiscoveryConnectorAttributesAPIService := discovery.NewConnectorAttributesAPIService(authorityRepo, log)
	DiscoveryConnectorAttributesAPIController := discovery.NewConnectorAttributesAPIController(DiscoveryConnectorAttributesAPIService)

	AuthorityConnectorAttributesAPIService := authority.NewConnectorAttributesAPIService(authorityRepo, log)
	AuthorityConnectorAttributesAPIController := authority.NewConnectorAttributesAPIController(AuthorityConnectorAttributesAPIService)

	HealthAPIService := health.NewHealthCheckAPIService()
	HealthAPIController := health.NewHealthCheckAPIController(HealthAPIService)

	topMux := http.NewServeMux()

	healthRouter := model.NewRouter(HealthAPIController)

	authorityRouter := model.NewRouter(AuthorityConnectorAttributesAPIController, AuthorityManagementAPIController, CertificateManagementAPIController)
	populateRoutes(authorityRouter, "authorityProvider")

	// needs to be separate as it uses v2 prefix!
	certificateRouter := model.NewRouter(CertificateManagementAPIController)
	populateRoutes(authorityRouter, "authorityProvider")

	discoveryRouter := model.NewRouter(DiscoveryConnectorAttributesAPIController, DiscoveryAPIController)
	populateRoutes(discoveryRouter, "discoveryProvider")

	info := []model.InfoResponse{
		{
			FunctionGroupCode: "discoveryProvider",
			Kinds:             []string{model.CONNECTOR_KIND},
			EndPoints:         routes["discoveryProvider"],
		},
		{
			FunctionGroupCode: "authorityProvider",
			Kinds:             []string{model.CONNECTOR_KIND},
			EndPoints:         routes["authorityProvider"],
		},
	}

	ConnectorInfoAPIService := connectorInfo.NewConnectorInfoAPIService(info)
	ConnectorInfoAPIController := connectorInfo.NewConnectorInfoAPIController(ConnectorInfoAPIService)
	connectorInfoRouter := model.NewRouter(ConnectorInfoAPIController)

	secretsRouter := secret.New()

	topMux.Handle("/v1", logMiddleware(connectorInfoRouter))
	topMux.Handle("/v1/", logMiddleware(healthRouter))
	topMux.Handle("/v1/authorityProvider/", logMiddleware(authorityRouter))
	topMux.Handle("/v2/authorityProvider/", logMiddleware(certificateRouter))
	topMux.Handle("/v1/discoveryProvider/", logMiddleware(discoveryRouter))
	topMux.Handle("/v1/secretProvider/", logMiddleware(secretsRouter.MuxRouter()))
	topMux.Handle("/v1/metrics", logMiddleware(promhttp.Handler()))

	var v2InfoHandler http.Handler = http.HandlerFunc(v2Info)
	topMux.Handle("/v2/", logMiddleware(v2InfoHandler))

	var v2commonHealthHandler http.Handler = http.HandlerFunc(v2commonHealth)
	topMux.Handle("/v2/health", logMiddleware(v2commonHealthHandler))
	topMux.Handle("/v2/health/readiness", logMiddleware(v2commonHealthHandler))
	topMux.Handle("/v2/health/liveness", logMiddleware(v2commonHealthHandler))

	err = http.ListenAndServe(":"+c.Server.Port, topMux)
	if err != nil {
		log.Fatal(err.Error())
	}

}

func logMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// retrieve the standard logger instance
		l := logger.Get()

		// create a correlation ID for the request
		correlationID := utils.GenerateRandomUUID()

		ctx := context.Background()
		ctx = zax.Set(ctx, []zap.Field{zap.String("correlation_id", correlationID)})

		r = r.WithContext(ctx)

		w.Header().Add("X-Correlation-ID", correlationID)

		r = r.WithContext(logger.WithCtx(ctx, l))

		log.Debug("Request received", zap.String("path", r.URL.Path))

		next.ServeHTTP(w, r)
	})
}

func populateRoutes(router *mux.Router, routeKey string) {
	routes[routeKey] = make([]model.EndpointDto, 0)
	err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		tpl, _ := route.GetPathTemplate()
		met, _ := route.GetMethods()
		name := route.GetName()
		endpoint := model.EndpointDto{
			Method:   met[0],
			Name:     strings.ToLower(string(name[0])) + name[1:],
			Uuid:     utils.DeterministicGUID(met[0] + tpl),
			Context:  tpl,
			Required: true,
		}
		log.Debug(strings.Join(met, ", ") + " " + tpl)
		routes[routeKey] = append(routes[routeKey], endpoint)
		return nil
	})
	if err != nil {
		log.Error("Unable to walk routers:" + err.Error())
	}
}

func v2commonHealth(w http.ResponseWriter, r *http.Request) {
	resp := sm.HealthInfo{
		Status: sm.UP,
	}
	b, err := json.Marshal(resp)
	if err != nil {
		log.Error("Failed to marshal v2 info endpoint response structure to json", zap.Error(err))
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func v2Info(w http.ResponseWriter, r *http.Request) {
	resp := sm.InfoResponse{
		Connector: sm.ConnectorInfo{
			Id:      "ilm.hashicorp.vault.secret.provider",
			Name:    "HashiCorp-Vault-Connector",
			Version: version,
		},
		Interfaces: []sm.ConnectorInterfaceInfo{
			{
				Code:    sm.ConnectorInterfaceInfoConst,
				Version: "v2",
			},
			{
				Code:    sm.ConnectorInterfaceHealthConst,
				Version: "v2",
			},
			{
				Code:    sm.ConnectorInterfaceMetricsConst,
				Version: "v1",
			},
			{
				Code:    sm.ConnectorInterfaceSecretConst,
				Version: "v1",
			},
		},
	}

	b, err := json.Marshal(resp)
	if err != nil {
		log.Error("Failed to marshal v2 info endpoint response structure to json", zap.Error(err))
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
