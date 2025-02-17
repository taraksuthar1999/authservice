//package com.example.authservice.configs;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.servlet.config.annotation.CorsRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//
//@Configuration
//public class CorsConfiguration implements WebMvcConfigurer {
//
//    @Override
//    public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping("/**")
//                .allowedOriginPatterns("*")// Allow CORS for all endpoints
////                .allowedOrigins("http://localhost:5173")  // React app origin (adjust if needed)
//                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")  // Allowed methods
//                .allowedHeaders("*")  // Allow any headers
//                .allowCredentials(true);  // Allow credentials (cookies, etc.)
//    }
//}
