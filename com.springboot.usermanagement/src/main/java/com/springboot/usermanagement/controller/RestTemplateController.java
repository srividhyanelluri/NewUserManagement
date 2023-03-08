package com.springboot.usermanagement.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.usermanagement.service.RestTemplateService;

@RestController
@RequestMapping("Rest")

public class RestTemplateController {
	
	@Autowired
	private RestTemplateService restTemplateService;

	

	@GetMapping("/users")
	public ResponseEntity<String> getAllUsers() {
		
		return restTemplateService.getAllUsers();		
}
//	
//	@GetMapping("users/{id}")
//	public ResponseEntity<String> getUserById() {
//		
//		return null;
//	}
}