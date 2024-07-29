package com.api.auth.persistence.repository;

import com.api.auth.persistence.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity,Long> {
    Optional<UserEntity> findUserEntityByUsername(String username);
}
