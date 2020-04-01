package com.mz.API.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mz.API.model.Rol;
import com.mz.API.model.RoleName;

public interface RolRepository extends JpaRepository<Rol, Long> {
	 Optional<Rol> findByName(RoleName roleName);
}
