package S05T02.interactive_cv.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/")
public class ApiController {

    @Autowired
    ServerCsrfTokenRepository csrfTokenRepository;

    private static final Logger log = LoggerFactory.getLogger(ApiController.class);

    @GetMapping("/csrf")
    public Mono<CsrfToken> csrf(ServerWebExchange exchange) {
        return csrfTokenRepository.loadToken(exchange)
                .switchIfEmpty(csrfTokenRepository.generateToken(exchange)
                        .flatMap(token -> csrfTokenRepository.saveToken(exchange, token).thenReturn(token)));
    }

    @PostMapping("/hola")
    public Mono<String> sayHello() {
        return Mono.just("hola");
    }
}
