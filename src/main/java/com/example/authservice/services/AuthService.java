package com.example.authservice.services;

import com.example.authservice.exceptions.UserAlreadyExistsException;
import com.example.authservice.exceptions.UserNotFoundException;
import com.example.authservice.exceptions.UserUnAuthorizedException;
import com.example.authservice.models.User;
import com.fasterxml.jackson.core.JsonProcessingException;

public interface AuthService {
    String login(User user);

    User signUp(User user);

    void verify(String token);
}
