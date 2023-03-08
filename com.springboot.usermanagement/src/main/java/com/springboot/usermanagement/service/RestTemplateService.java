package com.springboot.usermanagement.service;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@Service
public class RestTemplateService {

	@Value("${user.management.url}")
	private String userMgtUrl;

	RestTemplate restTemplate = new RestTemplate();

//	private static final String get_All_Users_URL = "http://10.1.10.33:8080/api/all";

//	Method to get all users
	public ResponseEntity<String> getAllUsers() {

		ResponseEntity<String> response = null;

		try {

			HttpHeaders headers = new HttpHeaders();

			headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

//		headers.add("Authorization", headerValue);

			HttpEntity<String> entity = new HttpEntity<String>("parameters", headers);

//		ResponseEntity<String> response = null;

			response = restTemplate.exchange(userMgtUrl, HttpMethod.GET, entity, String.class);

			String responseBody = response.getBody();

		} catch (HttpServerErrorException e) {

			e.getStatusCode();

			System.out.println("Remote Server Not Found: " + e.getMessage());
		}

		catch (ResourceAccessException e) {

			System.out.println("External Access Denied: " + e.getMessage());

		} catch (RestClientException e) {

			System.out.println("External Server Not Found: " + e.getMessage());

		} catch (Exception e) {

			System.out.println("Exception Occurred: " + e.getMessage());

		} finally {

			System.out.println("Finally Block is Executed");

		}

		return response;

//		if () {
//			throw new RuntimeException("External Server Not Connected");
//		} else {
//			return response;
//		}

	}

}

//	Method to get user by id
//	public ResponseEntity<String> getUserById(){
//		
//		return null;
//		
//	}
