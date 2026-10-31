package com.ikoyski.webtools.authserver.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Additional first-party browser clients. This lets a new Webtools application be registered
 * through Config Server configuration without adding another hard-coded seeder method.
 */
@Component
@ConfigurationProperties(prefix = "auth.clients")
public class ApplicationClientProperties {

    private List<ApplicationClient> applications = new ArrayList<>();

    public List<ApplicationClient> getApplications() {
        return applications;
    }

    public void setApplications(List<ApplicationClient> applications) {
        this.applications = applications == null ? new ArrayList<>() : applications;
    }

    public static class ApplicationClient {
        private String clientId;
        private String name;
        private List<String> redirectUris = new ArrayList<>();
        private List<String> scopes = new ArrayList<>();
        private String resourceUri;

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public List<String> getRedirectUris() { return redirectUris; }
        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris == null ? new ArrayList<>() : redirectUris;
        }
        public List<String> getScopes() { return scopes; }
        public void setScopes(List<String> scopes) { this.scopes = scopes == null ? new ArrayList<>() : scopes; }
        public String getResourceUri() { return resourceUri; }
        public void setResourceUri(String resourceUri) { this.resourceUri = resourceUri; }
    }
}
