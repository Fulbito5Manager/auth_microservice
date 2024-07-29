package com.api.auth.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users")
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String Username;
    private String password;
    @Column(name = "is_Enabled")
    private Boolean isEnabled;
    @Column(name = "account_No_Expired")
    private Boolean accountNoExpired;
    @Column(name = "account_No_Locked")
    private Boolean accountNoLocked;
    @Column(name = "credential_No_Expired")
    private Boolean credentialNoExpired;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleEntity> roles = new HashSet<>();
}
