package com.api.auth.persistence.repository;

import com.api.auth.persistence.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    List<RoleEntity> findRoleEntitiesByRoleEnumIn(List<String> roleNames);
}
