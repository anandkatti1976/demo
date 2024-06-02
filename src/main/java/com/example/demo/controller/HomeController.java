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

import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerifiers;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.IdTokenVerifier;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import java.security.SecureRandom;
import javax.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.math.BigInteger;

import com.example.demo.VO.OktaConfigurationVO;
import com.example.demo.VO.OktaTokensVO;
import com.example.demo.utils.TokenProcessorUtils;

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

    @Value("${okta.audience}")
    private String audience;

    private TokenProcessorUtils utils = new TokenProcessorUtils();

    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        
        String state = utils.generateStateValue();
        
        model.addAttribute("oauth2_state", state);
        session.setAttribute("oauth2_state", state);

        return "index";
    }

    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code, 
                            @RequestParam("state") String state, 
                            HttpSession session, 
                            Model model) {

         // Retrieve the stored state
         String storedState = (String) session.getAttribute("oauth2_state");

         // state parameter ensure that the endpoint cannot be called directly and 
         // avoidd CSRF
         if (storedState == null || !storedState.equals(state)) {
            // State parameter does not match or is missing
            throw new RuntimeException("Invalid state parameter");
        }
        System.out.println("code: " + code);

        OktaConfigurationVO oktaConfig = new OktaConfigurationVO(clientId, 
                                                                clientSecret, 
                                                                redirectUri, 
                                                                tokenUri, 
                                                                issuer,
                                                                audience);

        OktaTokensVO tokens = utils.generateTokens(oktaConfig, code, storedState);

        if (tokens == null) {
            throw new RuntimeException("Error generating tokens");
        }

        if (!utils.validateTokens(oktaConfig, tokens)) {
            throw new RuntimeException("Invalid ID token");
        }

        session.setAttribute("accessToken", tokens.getAccessToken());
        session.setAttribute("idToken", tokens.getIdToken());
        
        model.addAttribute("accessToken", tokens.getAccessToken());
        model.addAttribute("idToken", tokens.getIdToken());

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

}