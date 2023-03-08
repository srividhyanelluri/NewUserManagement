package com.springboot.usermanagement.entity;

import java.time.LocalDate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Getter;
import lombok.Setter;

	@Entity
	@Table(name="user_profile")
	@Setter
	@Getter
	
public class UserManagementEntity {

			@Id
			@GeneratedValue(strategy=GenerationType.AUTO)
			@Column(name="user_id")
			private Long userId;
			
			@Column(name="first_name")
			private String firstName;
			
			@Column(name="last_name")
			private String lastName;
			
			@Column(name="email")
			private String email;
			
			@Column(name="password")
			private String password;
			
			@Column(name="date_of_birth")
			private LocalDate dateOfBirth;
			
			@Column(name="gender")
			private String gender;
			
			
			



		


	}

