package com.example.authservice.services;

import com.example.authservice.exceptions.*;
import com.example.authservice.models.Roles;
import com.example.authservice.models.Session;
import com.example.authservice.models.User;
import com.example.authservice.repositories.RoleRepository;
import com.example.authservice.repositories.SessionRepository;
import com.example.authservice.repositories.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;

@Service
public class AuthServiceImpl implements AuthService{
    @Value("${jwt.secret}")
    private String  secretString;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final SessionRepository sessionRepository;
    private final RoleRepository rolesRepository;

    private final KafkaTemplate<String,String> kafkaTemplate;

    private final EmailTemplateService emailTemplateService;

    public AuthServiceImpl(UserRepository userRepository,
                           BCryptPasswordEncoder bCryptPasswordEncoder,
                           SessionRepository sessionRepository,
                           RoleRepository rolesRepository,
                           KafkaTemplate<String,String> kafkaTemplate,
                           EmailTemplateService emailTemplateService) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.rolesRepository = rolesRepository;
        this.kafkaTemplate = kafkaTemplate;
        this.emailTemplateService =emailTemplateService;
    }


    @Override
    public String login(User user){
        User userExists = userRepository.findByEmail(user.getEmail()).orElseThrow(
                () -> new UserUnAuthorizedException("User email/password incorrect.")
        );
        if(!bCryptPasswordEncoder.matches(user.getPassword(),userExists.getPassword()))
            throw new UserUnAuthorizedException("User email/password incorrect.");
        if(!userExists.getIsVerified())
            throw new UserUnAuthorizedException("User not verified. Please verify your email.");
        try{
            // build jwt secret key
            SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
            // create token
            Date issuedAt = new Date();
            Date expiryAt = new Date(issuedAt.getTime()+ 1000L *60*60*24);
            String jws = Jwts.builder()
                    .issuedAt(issuedAt)
                    .expiration(expiryAt)
                    .claim("user_id",userExists.getId())
                    .signWith(key)
                    .compact();
            // create newSession
            Session newSession = new Session();
            newSession.setToken(jws);
            newSession.setIssuedAt(issuedAt);
            newSession.setUser(userExists);
            newSession.setExpiryAt(expiryAt);
            sessionRepository.save(newSession);
            return jws;
        }catch (Exception e){
            throw new CreateLoginSessionException("Error in creating login session");
        }
    }

    @Override
    public User signUp(User user){
        userRepository.findByEmail(user.getEmail())
                .ifPresent(u -> {
                    throw new UserAlreadyExistsException("User Already exists with email: "+user.getEmail());
                });
        try{

            user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
            user.setVerifyToken(getJwtToken());
            user.getRoles().add(getRole("USER"));
            User savedUser =  userRepository.save(user);

            String htmlString = emailTemplateService.welcomeEmailHtmlString(
                    savedUser.getName(),
                    savedUser.getEmail(),
                    savedUser.getVerifyToken()
            );

            kafkaTemplate.send("user-signup",htmlString);
            return savedUser;
        }catch (JsonProcessingException e){
            throw new EmailTemplateException("Error in processing email template." + e.getMessage());
        }catch(Exception e){
            throw new UserSignUpErrorException("Error while signing up user." + e.getMessage());
        }
    }

    @Override
    public void verify(String token){
        User user = userRepository.findByVerifyToken(token)
                .orElseThrow(() -> new UserUnAuthorizedException("User verify token expired/invalid"));
        try{
            user.setIsVerified(true);
            userRepository.save(user);
            kafkaTemplate.send("create-user-cart",user.getId().toString());
        }catch(Exception e){
            throw new UserVerificationException("Error in verifying user." + e.getMessage());
        }
    }

    public Roles getRole(String name){
        Roles newRole = new Roles();
        newRole.setName(name);
        return rolesRepository.findByName(name)
                .orElseGet(() -> rolesRepository.save(newRole));
    }

    public String getJwtToken(){
        Date issuedAt = new Date();
        Date expiryAt = new Date(issuedAt.getTime()+ 1000L *60*60*24);
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
        return Jwts.builder()
                .issuedAt(issuedAt)
                .expiration(expiryAt)
                .signWith(key)
                .compact();
    }

}
