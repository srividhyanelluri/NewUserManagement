package com.springboot.usermanagement.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.usermanagement.dto.UserManagementDto;
import com.springboot.usermanagement.service.UserManagementService;

@RestController
public class UserManagementController {

	@Autowired
	private UserManagementService usermanagementService;

	@PostMapping("/users")
	public UserManagementDto saveUser(@RequestBody UserManagementDto userDto) {
		
		return usermanagementService.saveUserDetails(userDto) ;
	}

	@GetMapping("/users")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public List<UserManagementDto> getAllDetails() {
		List<UserManagementDto> dtoList = usermanagementService.getAllDetails();
		return dtoList;
	}
	
	@GetMapping("users/{id}")
	@PreAuthorize("hasAuthority('ROLE_USER')")
	public UserManagementDto getUserById(@PathVariable("id") Long id) {
		return usermanagementService.getUserById(id);
	}
	 
	@PutMapping("users/updateUser/{id}")
	public UserManagementDto updateUserDetails(@PathVariable("id") Long id,@RequestBody UserManagementDto userDto) {
		return usermanagementService.updateUserDetails(id,userDto);	
	}
	
	@DeleteMapping("users/{id}")
	public String deleteUserById(@PathVariable("id") Long id) {	
		 usermanagementService.deleteUserById(id);
		return "Deleted Id Successfully";
		
	}
	
}