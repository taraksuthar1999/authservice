package com.example.authservice.services;

import com.example.authservice.dtos.SendUserSignUpEmailDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
public class EmailTemplateServiceImpl implements EmailTemplateService {

    TemplateEngine templateEngine;
    ObjectMapper objectMapper;

    public EmailTemplateServiceImpl(TemplateEngine templateEngine, ObjectMapper objectMapper) {
        this.templateEngine = templateEngine;
        this.objectMapper = objectMapper;
    }

    @Override
    public String welcomeEmailHtmlString(String name, String toEmail, String token) throws JsonProcessingException {
        Context context = new Context();
        context.setVariable("name",name);
        context.setVariable("verificationLink","http://localhost:8080/auth/verify?token="+token);
        String body = templateEngine.process("welcome-email",context);
        SendUserSignUpEmailDto sendUserSignUpEmailDto = SendUserSignUpEmailDto
                .builder()
                .toEmail(toEmail)
                .subject("Welcome to our platform")
                .body(body)
                .build();
        return objectMapper.writeValueAsString(sendUserSignUpEmailDto);
    }
}
