package com.api.auth;

import com.api.auth.persistence.entity.PermissionEntity;
import com.api.auth.persistence.entity.RoleEntity;
import com.api.auth.persistence.entity.RoleEnum;
import com.api.auth.persistence.entity.UserEntity;
import com.api.auth.persistence.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Set;

@SpringBootApplication
@ComponentScan({"com.api.auth.*"})
public class AuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

	CommandLineRunner init(UserRepository userRepository,
						   PasswordEncoder passwordEncoder){
		return args -> {
			/*create permissions*/
			PermissionEntity createPermission = PermissionEntity.builder()
					.name("CREATE")
					.build();

			PermissionEntity readPermission = PermissionEntity.builder()
					.name("READ")
					.build();

			PermissionEntity updatePermission = PermissionEntity.builder()
					.name("UPDATE")
					.build();

			PermissionEntity deletePermission = PermissionEntity.builder()
					.name("DELETE")
					.build();

			PermissionEntity refactorPermission = PermissionEntity.builder()
					.name("REFACTOR")
					.build();

			/*create Roles*/
			RoleEntity roleAdmin = RoleEntity.builder()
					.roleEnum(RoleEnum.ADMIN)
					.permissionList(Set.of(createPermission,readPermission,updatePermission,deletePermission))
					.build();

			RoleEntity roleUser = RoleEntity.builder()
					.roleEnum(RoleEnum.USER)
					.permissionList(Set.of(createPermission,readPermission))
					.build();

			RoleEntity roleInvited = RoleEntity.builder()
					.roleEnum(RoleEnum.INVITED)
					.permissionList(Set.of(readPermission))
					.build();

			RoleEntity roleDeveloper = RoleEntity.builder()
					.roleEnum(RoleEnum.DEVELOPER)
					.permissionList(Set.of(createPermission,readPermission,updatePermission,deletePermission))
					.build();

			/* Create USERS */
			UserEntity userShamal = UserEntity.builder()
					.username("Shamal")
					//meCagoEnDiooos
					.password("$2a$10$QEE41un2vzF0wbw38tN/JOsb3ukm7SyNStHwE1SgK2X4UB/RJdcGS")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(roleAdmin))
					.build();

			UserEntity userLean = UserEntity.builder()
					.username("Lean")
					//porPajero
					.password("1234")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(roleDeveloper))
					.build();

			String encodedPassword = passwordEncoder.encode(userLean.getPassword());
			userLean.setPassword(encodedPassword);

			UserEntity userJoaquin = UserEntity.builder()
					.username("Joaquin")
					//patitasDeCachorro
					.password("$2a$10$C7M/ie85WlrZMXIV8QC9sOz013WcMaILleaxIWAhVjkfNhcyYs9Hm")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(roleInvited))
					.build();

			UserEntity userAndi = UserEntity.builder()
					.username("Andi")
					//ensartadoComoRanaMacho
					.password("$2a$10$oCb6RX01a/Ei//4UsdG9gO4MrAXjt4NeBOSJpkiHIp2rdBmS5aAES")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(roleUser))
					.build();

			userRepository.saveAll(List.of(userShamal,userLean,userAndi,userJoaquin));
		};

	}
}
