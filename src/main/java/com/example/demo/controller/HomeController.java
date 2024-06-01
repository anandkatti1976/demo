package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import java.security.SecureRandom;
import javax.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.math.BigInteger;

@Controller
public class HomeController {


    @Value("${okta.client-id}")
    private String clientId;

    @Value("${okta.client-secret}")
    private String clientSecret;

    @Value("${okta.redirect-uri}")
    private String redirectUri;

    @Value("${okta.token-uri}")
    private String tokenUri;

    @Value("${okta.issuer-uri}")
    private String issuer;

    private SecureRandom random = new SecureRandom();

    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        
        String state = new BigInteger(130, random).toString(32);
        
        model.addAttribute("oauth2_state", state);
        session.setAttribute("oauth2_state", state);
        return "index";
    }

    @GetMapping("/callback")
    public String callback(@RequestParam String code, @RequestParam("state") String state, HttpSession session, Model model) {


         // Retrieve the stored state
         String storedState = (String) session.getAttribute("oauth2_state");

         if (storedState == null || !storedState.equals(state)) {
            // State parameter does not match or is missing
            throw new RuntimeException("Invalid state parameter");
        }

        RestTemplate restTemplate = new RestTemplate();
        
        System.out.println("code: " + code);

        // Create Basic Auth header
        String authStr = clientId + ":" + clientSecret;
        String base64Creds = Base64.getEncoder().encodeToString(authStr.getBytes(StandardCharsets.UTF_8));

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Basic " + base64Creds);
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", code);
        body.add("redirect_uri", redirectUri);

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                tokenUri,
                HttpMethod.POST,
                entity,
                Map.class
        );

        Map<String, Object> tokens = response.getBody();
        String accessToken =  (String) tokens.get("access_token");
        String idToken =  (String) tokens.get("id_token");

        // Validate the ID token
        /*
        if (!validateIdToken(idToken)) {
            throw new RuntimeException("Invalid ID token");
        }
        */

        if (tokens != null) {
            session.setAttribute("accessToken", accessToken);
            session.setAttribute("idToken", idToken);
            model.addAttribute("accessToken", accessToken);
            model.addAttribute("idToken", idToken);
        }

        return "home";
    }

    @GetMapping("/secure/endpoint")
    public String secureEndpoint(HttpSession session, Model model) {
        String accessToken = (String) session.getAttribute("accessToken");
        if (accessToken == null) {
            return "redirect:/";
        }
        model.addAttribute("accessToken", accessToken);
        return "secure";
    }

    /**     
    private boolean validateIdToken(String idToken) {
        try {
            Jwt jwt = JwtVerifiers.accessTokenVerifierBuilder()
                    .setIssuer(issuer)
                    .setClientId(clientId)
                    .build()
                    .decode(idToken);
            return true; // Token is valid
        } catch (Exception e) {
            return false; // Token is invalid
        }
    }
    */
}