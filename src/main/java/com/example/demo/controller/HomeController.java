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
import com.example.demo.utils.Constants;
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

    /**
     * Generates the random state value to be used in the request
     * This ensures the /callback endpoint is not called in isolation. Also helps avoid CSRF. 
     * 
     * @param session
     * @param model
     * @return String - index.html
     */
    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        
        String state = utils.generateStateValue();
        
        model.addAttribute(Constants.OAUTH2_STATE, state);
        session.setAttribute(Constants.OAUTH2_STATE, state);

        return "index";
    }

    
    /**
     * Endpoint for redirect URI parameter configure for the OKTA application. Ensure to import
     * Okta base certificate into cacert to make HTTPS Calls to Okta
     * 
     * @param code
     * @param state
     * @param session
     * @param model
     * @return String - home.html
     */

    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code, 
                            @RequestParam("state") String state, 
                            HttpSession session, 
                            Model model) {

         // Retrieve the stored state
         String storedState = (String) session.getAttribute(Constants.OAUTH2_STATE);

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

        session.setAttribute(Constants.ACCESS_TOKEN, tokens.getAccessToken());
        session.setAttribute(Constants.ID_TOKEN, tokens.getIdToken());
        
        model.addAttribute(Constants.ACCESS_TOKEN, tokens.getAccessToken());
        model.addAttribute(Constants.ID_TOKEN, tokens.getIdToken());

        return "home";
    }

    /**
     * Secure endpoint that requires an access token to be present in the session
     * 
     * @param session
     * @param model
     * @return String - secure.html
     */
    @GetMapping("/vis")
    public String visEndpoint(HttpSession session, Model model) {
        
        String accessToken = (String) session.getAttribute(Constants.ACCESS_TOKEN);
        if (accessToken == null) {
            return "redirect:/";
        }
         
        model.addAttribute(Constants.ACCESS_TOKEN, session.getAttribute(Constants.ACCESS_TOKEN));
        model.addAttribute(Constants.ID_TOKEN, session.getAttribute(Constants.ID_TOKEN));
        return "vis";
    }

    @GetMapping("/secure/endpoint")
    public String secureEndpoint(HttpSession session, Model model) {
        
        String accessToken = (String) session.getAttribute(Constants.ACCESS_TOKEN);
        if (accessToken == null) {
            return "redirect:/";
        }
         
        model.addAttribute(Constants.ACCESS_TOKEN, session.getAttribute(Constants.ACCESS_TOKEN));
        model.addAttribute(Constants.ID_TOKEN, session.getAttribute(Constants.ID_TOKEN));
        return "secure";
    }


}