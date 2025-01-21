package com.example.authservice.exceptions;

public class InvalidUserLoginDetails extends RuntimeException {
    public InvalidUserLoginDetails(String s) {
        super(s);
    }
}
