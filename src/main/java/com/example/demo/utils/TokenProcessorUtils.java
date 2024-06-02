package com.example.demo.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerifiers;

import com.example.demo.VO.OktaConfigurationVO;
import com.example.demo.VO.OktaTokensVO;


public class TokenProcessorUtils {

    /**
     * 
     * @return
     */
    public String generateStateValue() {
        SecureRandom random = new SecureRandom();
        String state = new BigInteger(130, random).toString(32);
        return state;
    }

    /**
     * 
     * @param oktaConfig
     * @param authCode
     * @param state
     * @return
     */
    public OktaTokensVO generateTokens(OktaConfigurationVO oktaConfig, String authCode, String state) {

        RestTemplate restTemplate = new RestTemplate();
        // Create Basic Auth header
        String authStr = oktaConfig.getClientId() + ":" + oktaConfig.getClientSecret();
        String base64Creds = Base64.getEncoder().encodeToString(authStr.getBytes(StandardCharsets.UTF_8));

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Basic " + base64Creds);
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", Constants.AUTHORIZATION_CODE);
        body.add("code", authCode);
        body.add("redirect_uri", oktaConfig.getRedirectUri());

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                oktaConfig.getTokenUri(),
                HttpMethod.POST,
                entity,
                Map.class
        );

        Map<String, Object> tokens = response.getBody();
        String accessToken =  (String) tokens.get("access_token");
        String idToken =  (String) tokens.get("id_token");

        OktaTokensVO oktaTokensVO = null;

        if (accessToken != null && idToken != null) {
            oktaTokensVO = new OktaTokensVO(accessToken, idToken);
        }
        
        return oktaTokensVO;
    }

    public boolean validateTokens(OktaConfigurationVO oktaConfig,
                                  OktaTokensVO oktaTokensVO) {
    
        try {
            AccessTokenVerifier jwtVerifier = JwtVerifiers.accessTokenVerifierBuilder()
                    .setIssuer(oktaConfig.getIssuer())
                    .setAudience(oktaConfig.getAudience())
                    .build();                    
                    
            Jwt accessJwt = jwtVerifier.decode(oktaTokensVO.getAccessToken());

            // Tokens are valid
            return true;
        } catch (Exception e) {
            // Tokens are invalid
            return false;
        }
    }
   
}
