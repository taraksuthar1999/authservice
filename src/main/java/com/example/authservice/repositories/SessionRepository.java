package com.example.authservice.repositories;

import com.example.authservice.models.Session;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<Session,Long> {
    Session save(Session session);
}
