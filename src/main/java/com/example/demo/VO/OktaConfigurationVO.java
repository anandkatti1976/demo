package com.example.demo.VO;


public class OktaConfigurationVO {

    private String clientId;

    private String clientSecret;

    private String redirectUri;

    private String tokenUri;

    private String issuer;

    private String audience;

    public OktaConfigurationVO(String clientId,
                                String clientSecret,
                                String redirectUri,
                                String tokenUri,
                                String issuer,
                                String audience) {

        this.tokenUri = tokenUri;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.issuer = issuer;
        this.audience = audience;
    }
                            
    public String getTokenUri() {
        return tokenUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getAudience() {
        return audience;
    }
}

