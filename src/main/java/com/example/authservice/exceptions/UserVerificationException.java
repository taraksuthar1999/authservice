package com.example.authservice.exceptions;

public class UserVerificationException extends RuntimeException {
    public UserVerificationException(String message) {
        super(message);
    }
}
