package com.example.authservice.controllers;

import com.example.authservice.dtos.*;
import com.example.authservice.dtos.ResponseStatus;
import com.example.authservice.models.User;
import com.example.authservice.services.AuthService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;


@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthService authService;

    @Value("${VERIFIED_REDIRECT_URI}")
    private String VERIFIED_REDIRECT_URI;

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
    public RedirectView verify(@RequestParam String token){
            authService.verify(token);
            return new RedirectView(VERIFIED_REDIRECT_URI);
    }
    @GetMapping("/validate")
    public String verify(){
        System.out.println("in validate method");
            return "validated";
    }


}
