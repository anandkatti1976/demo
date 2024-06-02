package com.example.demo.VO;

public class OktaTokensVO {

    private String accessToken;
    private String idToken;


    public OktaTokensVO(String accessToken, String idToken) {
        this.accessToken = accessToken;
        this.idToken = idToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getIdToken() {
        return idToken;
    }

}
