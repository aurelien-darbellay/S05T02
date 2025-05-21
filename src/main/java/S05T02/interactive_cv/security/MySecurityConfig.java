package S05T02.interactive_cv.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;


@Configuration
public class MySecurityConfig {

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http, CorsConfigurationSource corsConfig, ServerCsrfTokenRepository csrfTokenRepository, ServerAuthenticationSuccessHandler authenticationSuccessHandler) throws Exception {
        http
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .cors(cors -> cors.configurationSource(corsConfig))
                //.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .csrf(csrf ->
                        csrf.csrfTokenRepository(csrfTokenRepository)
                                .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler())
                )
                .authorizeExchange(exchanges ->
                        exchanges
                                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                                .pathMatchers("/login", "/hola", "/csrf").permitAll()
                                .anyExchange().authenticated()
                )
                .formLogin(form -> form
                        .authenticationSuccessHandler(authenticationSuccessHandler));
        return http.build();
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of("http://localhost:5173", "http://localhost:8080"));  // your front-end origin
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-XSRF-TOKEN"));
        cfg.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", cfg);
        return src;
    }


    @Bean
    public ServerCsrfTokenRepository csrfTokenRepository() {
        CookieServerCsrfTokenRepository csrfTokenRepository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
        csrfTokenRepository.setCookieCustomizer(builder -> builder
                .sameSite("None")   // or "Lax", "None"
                .secure(true)         // important if using SameSite=None
                .path("/")            // optional, sets cookie path
        );
        return csrfTokenRepository;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();

    }

    @Bean
    ServerAuthenticationSuccessHandler authenticationSuccessHandler() {
        return (webFilterExchange, authentication) ->
                Mono.defer(() -> {
                    ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
                    response.setStatusCode(HttpStatus.SEE_OTHER);
                    response.getHeaders().setLocation(URI.create("/csrf"));
                    return response.setComplete();
                });
    }
}



