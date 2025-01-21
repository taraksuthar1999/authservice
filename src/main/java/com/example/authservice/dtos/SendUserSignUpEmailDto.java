package com.example.authservice.dtos;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonSerialize
public class SendUserSignUpEmailDto {
    private String toEmail;
    private String subject;
    private String body;
}
