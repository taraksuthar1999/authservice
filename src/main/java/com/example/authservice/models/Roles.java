package com.example.authservice.models;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
public class Roles extends BaseModel{
    @Column(nullable = false,unique = true)
    private String name;
}
