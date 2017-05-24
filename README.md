package org.fm.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.fm.model.security.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
