package com.api.auth.service;

import com.api.auth.persistence.entity.UserEntity;
import com.api.auth.persistence.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;

public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findUserEntityByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("El usuario " + username + " no existe"));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        userEntity.getRoles()
                .forEach(roleEntity -> authorityList.add(new SimpleGrantedAuthority("Role_".concat(roleEntity.getRoleEnum().name()))));

        userEntity.getRoles().stream()
                .flatMap(roleEntity -> roleEntity.getPermissionList().stream())
                .forEach(permissionEntity -> authorityList.add(new SimpleGrantedAuthority(permissionEntity.getName())));

        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.getIsEnabled(),
                userEntity.getAccountNoExpired(),
                userEntity.getCredentialNoExpired(),
                userEntity.getAccountNoLocked(),
                authorityList);
    }
}
