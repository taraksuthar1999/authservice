package com.example.authservice.dtos;

import com.example.authservice.models.User;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserLoginRequestDto {
    private String email;
    private String password;

    public User toUser(){
        User user = new User();
        user.setPassword(this.password);
        user.setEmail(this.email);
        return user;
    }

}
