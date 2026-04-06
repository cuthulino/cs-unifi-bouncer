package main

import (
	"context"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csversion "github.com/crowdsecurity/go-cs-lib/version"
	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog/log"
)

type metricsCollector struct {
	mal               *unifiAddrList
	lastPollTimeMilli int64
	lastPollTime      int64
	startupTime       int64
	version           string
	osName            string
	osVersion         string
}

func newMetricsCollector(mal *unifiAddrList, version string) *metricsCollector {
	osName, osVersion := csversion.DetectOS()
	return &metricsCollector{
		mal:               mal,
		lastPollTimeMilli: time.Now().UnixMilli(),
		lastPollTime:      time.Now().Unix(),
		startupTime:       time.Now().Unix(),
		version:           version,
		osName:            osName,
		osVersion:         osVersion,
	}
}

func (mc *metricsCollector) pollAndSendMetrics(ctx context.Context, api *apiclient.ApiClient) {
	nowMilli := time.Now().UnixMilli()
	now := time.Now().Unix()

	req := &unifi.TrafficFlowsRequest{
		Action:        []string{"blocked"},
		TimestampFrom: mc.lastPollTimeMilli,
		TimestampTo:   nowMilli,
		PageSize:      1000,
		PageNumber:    0,
	}

	var dropped int64 = 0

	for {
		flows, err := mc.mal.c.GetTrafficFlows(ctx, unifiSite, req)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to fetch traffic flows for metrics from UniFi")
			return
		}

		for _, flow := range flows.Data {
			if flow.Action == "blocked" {
				for _, policy := range flow.Policies {
					if strings.Contains(policy.Name, "cs-unifi-bouncer") {
						dropped++
						break
					}
				}
			}
		}

		if !flows.HasNext {
			break
		}

		req.PageNumber++
	}
	log.Info().Msgf("Processed %d new blocked traffic events from UniFi, reporting to CrowdSec", dropped)

	nameDropped := "dropped"
	// nameActiveDecisions := "active_decisions"
	unitRequest := "request"
	valueDropped := float64(dropped)
	// valueActiveDecisions := float64(len(mc.mal.blockedAddresses[true]) + len(mc.mal.blockedAddresses[false]))

	window := now - mc.lastPollTime

	payload := &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{
			{
				Name: "cs-unifi-bouncer",
				Type: "daemon bouncer",
				BaseMetrics: models.BaseMetrics{
					Version:             &mc.version,
					UtcStartupTimestamp: &mc.startupTime,
					FeatureFlags:        []string{},
					Os: &models.OSversion{
						Name:    &mc.osName,
						Version: &mc.osVersion,
					},
					Metrics: []*models.DetailedMetrics{
						{
							Items: []*models.MetricsDetailItem{
								{
									Name:  &nameDropped,
									Unit:  &unitRequest,
									Value: &valueDropped,
									Labels: map[string]string{
										"origin":      "crowdsec",
										"remediation": "ban",
									},
								},
								// {
								// 	Name:  &nameActiveDecisions,
								// 	Value: &valueActiveDecisions,
								// },
							},
							Meta: &models.MetricsMeta{
								UtcNowTimestamp:   &now,
								WindowSizeSeconds: &window,
							},
						},
					},
				},
			},
		},
	}

	_, _, err := api.UsageMetrics.Add(ctx, payload)
	switch {
	case err != nil:
		log.Warn().Err(err).Msg("failed to send metrics")
	default:
		mc.lastPollTimeMilli = nowMilli
		mc.lastPollTime = now
		log.Debug().Msg("usage metrics successfully sent")
	}
}
