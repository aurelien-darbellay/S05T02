package S05T02.interactive_cv.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class UserDetailsService implements ReactiveUserDetailsService {

    @Autowired
    MockUserDetails mockUserDetails;

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.just(mockUserDetails);
    }
}
