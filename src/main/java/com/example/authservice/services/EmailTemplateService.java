package com.example.authservice.services;

import com.fasterxml.jackson.core.JsonProcessingException;

public interface EmailTemplateService {
    String welcomeEmailHtmlString(String name, String toEmail, String token) throws JsonProcessingException;
}
