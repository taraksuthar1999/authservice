package com.example.authservice.security.models;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.Set;

public class CustomSecurityUserDeserializer extends JsonDeserializer<CustomSecurityUserDetails> {
    private static final TypeReference<Set<SimpleGrantedAuthority>> SIMPLE_GRANTED_AUTHORITY_SET = new TypeReference<Set<SimpleGrantedAuthority>>() {
    };

    CustomSecurityUserDeserializer() {
    }

    public CustomSecurityUserDetails deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        ObjectMapper mapper = (ObjectMapper)jp.getCodec();
        JsonNode jsonNode = (JsonNode)mapper.readTree(jp);
        Set<? extends GrantedAuthority> authorities = (Set)mapper.convertValue(jsonNode.get("authorities"), SIMPLE_GRANTED_AUTHORITY_SET);
        JsonNode passwordNode = this.readJsonNode(jsonNode, "password");
        String username = this.readJsonNode(jsonNode, "username").asText();
        String profile = this.readJsonNode(jsonNode, "profile").asText();
        String name = this.readJsonNode(jsonNode, "name").asText();
        Long id = this.readJsonNode(jsonNode,"id").asLong();
        String password = passwordNode.asText("");
        boolean enabled = this.readJsonNode(jsonNode, "enabled").asBoolean();
        boolean accountNonExpired = this.readJsonNode(jsonNode, "accountNonExpired").asBoolean();
        boolean credentialsNonExpired = this.readJsonNode(jsonNode, "credentialsNonExpired").asBoolean();
        boolean accountNonLocked = this.readJsonNode(jsonNode, "accountNonLocked").asBoolean();
        CustomSecurityUserDetails result = new CustomSecurityUserDetails(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities, profile, name, id);
//        if (passwordNode.asText((String)null) == null) {
//            result.eraseCredentials();
//        }

        return result;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return (JsonNode)(jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance());
    }
}
