package S05T02.interactive_cv.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

@Component
public class MockUserDetails implements UserDetails {
    @Autowired
    PasswordEncoder passwordEncoder;
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return passwordEncoder.encode("my_password");
    }

    @Override
    public String getUsername() {
        return "user";
    }
}
