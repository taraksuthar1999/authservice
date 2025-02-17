package com.example.authservice.controllers;

import com.example.authservice.dtos.*;
import com.example.authservice.dtos.ResponseStatus;
import com.example.authservice.exceptions.UserUnAuthorizedException;
import com.example.authservice.models.User;
import com.example.authservice.repositories.UserRepository;
import com.example.authservice.security.models.CustomSecurityUserDetails;
import com.example.authservice.services.AuthService;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.web.bind.annotation.*;


import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthService authService;

    private final RegisteredClientRepository registeredClientRepository;

    public AuthController(AuthService authService, RegisteredClientRepository registeredClientRepository) {
        this.authService = authService;
        this.registeredClientRepository = registeredClientRepository;
    }


    @PostMapping("/login")
    public ResponseEntity<ResponseDto<Object>> login(@RequestBody UserLoginRequestDto userLoginRequestDto){
            String token = authService.login(userLoginRequestDto.toUser());
            ResponseDto<Object> responseDto = new ResponseDto<>();
            responseDto.setStatus(ResponseStatus.SUCCESS);
            responseDto.setMessage("logged in successfully.");
            return ResponseEntity.ok().header("Authorization",token).body(responseDto);
    }

    @PostMapping("/signup")
    public ResponseEntity<ResponseDto<UserResponseDto>>  signUp(@RequestBody UserSignUpRequestDto userSignUpRequestDto){
            User user = userSignUpRequestDto.toUser();
            User signedUpUser = authService.signUp(user);
            return ResponseEntity.ok()
                    .body(new ResponseDto<>(ResponseStatus.SUCCESS,
                            "Registered successfully. Email sent for verification.",
                            UserResponseDto.FromUser(signedUpUser)));
    }

    @GetMapping("/verify")
    public ResponseEntity<ResponseDto<Object>> verify(@RequestParam String token){
            authService.verify(token);
            return ResponseEntity.ok()
                    .body(new ResponseDto<>(
                        ResponseStatus.SUCCESS,
                        "User verified successfully.",
                        null)
                    );
    }
    @GetMapping("/validate")
    public String verify(){
        System.out.println("in validate method");
            return "validated";
    }


}
