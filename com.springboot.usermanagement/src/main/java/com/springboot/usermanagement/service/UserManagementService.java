package com.springboot.usermanagement.service;

import java.util.List;

import com.springboot.usermanagement.dto.UserManagementDto;
import com.springboot.usermanagement.entity.UserManagementEntity;

public interface UserManagementService {


	List<UserManagementDto> getAllDetails();

	UserManagementDto saveUserDetails(UserManagementDto userDto);

	UserManagementDto getUserById(Long id);

	UserManagementDto updateUserDetails(Long id, UserManagementDto userDto);

	void deleteUserById(Long id);

}
