package com.example.authservice.models;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Entity
@Setter
@Getter
public class Session extends BaseModel{
    @ManyToOne
    private User user;
    private String token;
    private String ipAddress;
    private Date expiryAt;
    private Date issuedAt;
}
