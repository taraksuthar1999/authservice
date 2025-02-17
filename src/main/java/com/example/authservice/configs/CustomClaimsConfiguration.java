package com.example.authservice.configs;

import com.example.authservice.security.models.CustomSecurityUserDetails;
import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
@Configuration
public class CustomClaimsConfiguration {

        @Bean
        public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
            return (context) -> {
                if ("id_token".equals(context.getTokenType().getValue())) {
                    var principle = context.getPrincipal().getPrincipal();
                    context.getClaims().claims((claims) -> {
                        if(principle instanceof CustomSecurityUserDetails userDetails){
//                            claims.put("roles",oauth2.getAuthorities());
                            claims.put("name", userDetails.getName());
                            claims.put("email", userDetails.getUsername());
                            claims.put("profile",userDetails.getProfile());
                        }
                    });
                }

                if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())){
                    var principle = context.getPrincipal();
                    var userDetails = (CustomSecurityUserDetails) principle.getPrincipal();
                    context.getClaims().claims((claims) -> {
                        claims.put("roles",principle.getAuthorities());
                        claims.put("id", userDetails.getId());
                    });
                }
            };
        }

}
