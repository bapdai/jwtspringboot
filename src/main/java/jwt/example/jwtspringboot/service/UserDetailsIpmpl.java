package jwt.example.jwtspringboot.service;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jwt.example.jwtspringboot.entity.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Getter
public class UserDetailsIpmpl implements UserDetails {

    public static final long serialVersionUID = 1L;

    private Long id;

    private String username;


    private String email;

    @JsonIgnore
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsIpmpl(Long id, String username, String email, String password,
                            Collection<? extends GrantedAuthority> authorities){
        this.id= id;
        this.username=username;
        this.email=email;
        this.password=password;
        this.authorities=authorities;
    }

    public static UserDetailsIpmpl build(User user){
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UserDetailsIpmpl(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o){
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsIpmpl user = (UserDetailsIpmpl) o;
        return Objects.equals(id, user.id);
    }
}
