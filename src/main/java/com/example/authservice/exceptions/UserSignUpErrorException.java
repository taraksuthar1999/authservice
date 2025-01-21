package com.example.authservice.exceptions;

public class UserSignUpErrorException extends RuntimeException {
    public UserSignUpErrorException(String message) {
        super(message);
    }
}
