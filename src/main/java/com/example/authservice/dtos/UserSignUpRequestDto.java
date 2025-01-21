package com.example.authservice.dtos;

import com.example.authservice.models.User;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserSignUpRequestDto {
    private String name;
    private String email;
    private String password;
    private String profile;

    public User toUser(){
        User user = new User();
        user.setName(this.name);
        user.setEmail(this.email);
        user.setPassword(this.password);
        user.setProfile(this.profile);
        return user;
    }



}
