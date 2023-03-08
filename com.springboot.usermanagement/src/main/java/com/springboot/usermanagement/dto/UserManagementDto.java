package com.springboot.usermanagement.dto;

import java.time.LocalDate;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
@Data


public class UserManagementDto {
	

	private Long userId;
	
	private String firstName;
	
	private String lastName;
	
	private String email;
	
	private String password;
	
	private LocalDate dateOfBirth;
	
	private String gender;
	
	}
	


