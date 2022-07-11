package jwt.example.jwtspringboot.repository;

import jwt.example.jwtspringboot.util.ERole;
import jwt.example.jwtspringboot.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    /*
    * Find role by name
    * @param name
    * return role
    * */
    Optional<Role> findByName(ERole name);
}
