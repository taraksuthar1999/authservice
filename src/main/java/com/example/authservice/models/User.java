package com.example.authservice.models;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.List;

@Entity
@Setter
@Getter
public class User extends BaseModel {

    @Column(nullable = false)
    private String name;
    @Column(nullable = false, unique = true)
    private String email;
    @Column(nullable = false)
    private String password;
    @Column(nullable = false)
    private String profile;
    @Column(columnDefinition = "Boolean default false")
    private Boolean isVerified = false;
    private String verifyToken;
    @ManyToMany(fetch = FetchType.EAGER)
    private List<Roles> roles;
}
