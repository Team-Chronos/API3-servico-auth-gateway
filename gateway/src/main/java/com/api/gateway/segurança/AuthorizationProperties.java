package com.api.gateway.segurança;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "auth")
public class AuthorizationProperties {
    private List<String> publicPaths = new ArrayList<>();
    private RateLimits rateLimits = new RateLimits();
    private List<Rule> rules = new ArrayList<>();

    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> publicPaths) { this.publicPaths = publicPaths; }

    public RateLimits getRateLimits() { return rateLimits; }
    public void setRateLimits(RateLimits rateLimits) { this.rateLimits = rateLimits; }

    public List<Rule> getRules() { return rules; }
    public void setRules(List<Rule> rules) { this.rules = rules; }

    public static class RateLimits {
        private int perToken = 100;
        private int perIp = 200;

        public int getPerToken() { return perToken; }
        public void setPerToken(int perToken) { this.perToken = perToken; }
        public int getPerIp() { return perIp; }
        public void setPerIp(int perIp) { this.perIp = perIp; }
    }

    public static class Rule {
        private String path;
        private List<String> methods = new ArrayList<>();
        private List<String> roles = new ArrayList<>();

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public List<String> getMethods() { return methods; }
        public void setMethods(List<String> methods) { this.methods = methods; }
        public List<String> getRoles() { return roles; }
        public void setRoles(List<String> roles) { this.roles = roles; }
    }
}