package com.example.authservice.security.services;

import com.example.authservice.models.User;
import com.example.authservice.repositories.UserRepository;
import com.example.authservice.security.models.CustomSecurityUserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CustomSecurityUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;

    public CustomSecurityUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username).orElseThrow(
                () -> new UsernameNotFoundException("User details with given username is not found")
        );
        Collection<SimpleGrantedAuthority> roles = user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
        return new CustomSecurityUserDetails(user.getEmail(),user.getPassword(),roles,user.getProfile(),user.getName(),user.getId());
    }
}
