package com.springboot.usermanagement.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.springboot.usermanagement.dto.UserManagementDto;
import com.springboot.usermanagement.entity.UserManagementEntity;

@Repository

public interface UserManagementRepository extends JpaRepository<UserManagementEntity, Long>{

//	void updateUserDetails(UserManagementDto user);

}
