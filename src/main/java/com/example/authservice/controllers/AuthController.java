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
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;


import java.util.Set;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }


    @PostMapping("/login")
    public ResponseEntity<ResponseDto<Object>> login(@RequestBody UserLoginRequestDto userLoginRequestDto){
        try{
            String token = authService.login(userLoginRequestDto.toUser());
            ResponseDto<Object> responseDto = new ResponseDto<>();
            responseDto.setStatus(ResponseStatus.SUCCESS);
            responseDto.setMessage("logged in successfully.");


            return ResponseEntity.ok().header("Authorization",token).body(responseDto);
        }catch(UserUnAuthorizedException e){
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ResponseDto<>(ResponseStatus.FAILURE,e.getMessage(),null));
        } catch (Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseDto<>(ResponseStatus.FAILURE,"User login error. "+e.getMessage(),null));
        }

    }

    @PostMapping("/signup")
    public ResponseEntity<ResponseDto<UserResponseDto>>  signUp(@RequestBody UserSignUpRequestDto userSignUpRequestDto){
        try{
            User user = userSignUpRequestDto.toUser();
            User signedUpUser = authService.signUp(user);
            return ResponseEntity.ok()
                    .body(new ResponseDto<>(ResponseStatus.SUCCESS,
                            "User created successfully.",
                            UserResponseDto.FromUser(signedUpUser)));
        }catch (Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseDto<>(ResponseStatus.FAILURE,"User sign up error. "+e.getMessage(),null));
        }
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

    @PostMapping("/validate")
    public String verify(){
        System.out.println("in validate method");
            return "validated";
    }


}
