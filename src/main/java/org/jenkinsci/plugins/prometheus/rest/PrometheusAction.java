package org.jenkinsci.plugins.prometheus.rest;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.util.HttpResponses;
import io.prometheus.client.exporter.common.TextFormat;
import jenkins.metrics.api.Metrics;
import jenkins.model.Jenkins;

import com.google.common.base.Charsets;
import com.google.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.prometheus.config.PrometheusConfiguration;
import org.jenkinsci.plugins.prometheus.service.PrometheusMetrics;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import java.util.Base64;

@Extension
public class PrometheusAction implements UnprotectedRootAction {

    private PrometheusMetrics prometheusMetrics;

    @Inject
    public void setPrometheusMetrics(PrometheusMetrics prometheusMetrics) {
        this.prometheusMetrics = prometheusMetrics;
    }

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return "Prometheus Metrics Exporter";
    }

    @Override
    public String getUrlName() {
        return PrometheusConfiguration.get().getUrlName();
    }

    public HttpResponse doDynamic(StaplerRequest request) {
        if (request.getRestOfPath().equals(PrometheusConfiguration.get().getAdditionalPath())) {
            if (hasAccess(request)) {
                return prometheusResponse();
            }
            return HttpResponses.forbidden();
        }
        return HttpResponses.notFound();
    }

    private boolean hasAccess(StaplerRequest request) {
        PrometheusConfiguration configuration = PrometheusConfiguration.get();

        if (configuration.isUseBasicAuthenticatedEndpoint()) {
            String authenticationHeader = request.getHeader("Authorization");
            if (StringUtils.isNotEmpty(authenticationHeader) && authenticationHeader.trim().startsWith("Basic")) {
                String base64Credentials = authenticationHeader.trim().substring("Basic".length()).trim();
                String decodedCredentials = new String(Base64.getDecoder().decode(base64Credentials),
                        Charsets.ISO_8859_1);
                String[] credentials = decodedCredentials.split(":");

                if (credentials.length == 2) {
                    return StringUtils.equals(credentials[0], configuration.getBasicAuthenticationUsername()) &&
                            StringUtils.equals(credentials[1], configuration.getBasicAuthenticationPassword());
                }
            }
            // If the user may be using some other form of authentication, continue execution,
            // otherwise we block access.
            if (!configuration.isUseAuthenticatedEndpoint()) {
                return false;
            }
        }

        if (configuration.isUseAuthenticatedEndpoint()) {
            return Jenkins.getInstance().hasPermission(Metrics.VIEW);
        }
        return true;
    }

    private HttpResponse prometheusResponse() {
        return (request, response, node) -> {
            response.setStatus(StaplerResponse.SC_OK);
            response.setContentType(TextFormat.CONTENT_TYPE_004);
            response.addHeader("Cache-Control", "must-revalidate,no-cache,no-store");
            response.getWriter().write(prometheusMetrics.getMetrics());
        };
    }
}
