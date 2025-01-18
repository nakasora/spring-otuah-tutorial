package com.example.keycloak.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import org.springframework.lang.NonNull;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractClientRoles(jwt).stream()).collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities);
    }

    @SuppressWarnings("unchecked")
    private Collection<? extends GrantedAuthority> extractClientRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (!(resourceAccess instanceof Map)) {
            return Set.of();
        }

        Map<String, Object> clientConfig = (Map<String, Object>) resourceAccess.get("news_app_client");
        if (!(clientConfig instanceof Map)) {
            return Set.of();
        }

        Collection<String> roles = (Collection<String>) clientConfig.get("roles");
        if (!(roles instanceof Collection)) {
            return Set.of();
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }
}
